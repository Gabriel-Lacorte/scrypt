use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Table, TableState, Wrap},
    Frame, Terminal,
};
use sc_pcap::AnalyzedPacket;
use sc_protocol::{DissectionTree, ProtocolNode, model};
use std::io;
use tracing::debug;

/// Application state for the TUI.
pub struct App {
    /// All analyzed packets
    packets: Vec<AnalyzedPacket>,
    /// State for the packet list table
    packet_table_state: TableState,
    /// State for the protocol tree list
    tree_list_state: ListState,
    /// Currently selected packet index
    selected_packet: Option<usize>,
    /// Active pane
    active_pane: Pane,
    /// Display filter text
    filter_text: String,
    /// Whether filter input is active
    filter_editing: bool,
    /// Filtered packet indices
    filtered_indices: Vec<usize>,
    /// Should quit
    should_quit: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pane {
    PacketList,
    ProtocolTree,
    HexDump,
}

impl App {
    pub fn new(packets: Vec<AnalyzedPacket>) -> Self {
        let indices: Vec<usize> = (0..packets.len()).collect();
        let mut state = TableState::default();
        if !packets.is_empty() {
            state.select(Some(0));
        }
        Self {
            packets,
            packet_table_state: state,
            tree_list_state: ListState::default(),
            selected_packet: if indices.is_empty() { None } else { Some(0) },
            active_pane: Pane::PacketList,
            filter_text: String::new(),
            filter_editing: false,
            filtered_indices: indices,
            should_quit: false,
        }
    }

    /// Run the TUI event loop.
    pub fn run(mut self) -> io::Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        while !self.should_quit {
            terminal.draw(|f| self.draw(f))?;
            if event::poll(std::time::Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    self.handle_key(key);
                }
            }
        }

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        Ok(())
    }

    fn draw(&mut self, f: &mut Frame) {
        let size = f.area();

        // Main layout: packet list on top, bottom split into tree + hex
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),      // Filter bar
                Constraint::Percentage(45), // Packet list
                Constraint::Percentage(55), // Bottom panes
            ])
            .split(size);

        let bottom_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(50), // Protocol tree
                Constraint::Percentage(50), // Hex dump
            ])
            .split(main_chunks[2]);

        self.draw_filter_bar(f, main_chunks[0]);
        self.draw_packet_list(f, main_chunks[1]);
        self.draw_protocol_tree(f, bottom_chunks[0]);
        self.draw_hex_dump(f, bottom_chunks[1]);
    }

    fn draw_filter_bar(&self, f: &mut Frame, area: Rect) {
        let style = if self.filter_editing {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let text = if self.filter_text.is_empty() {
            "Press / to filter...".to_string()
        } else {
            format!("Filter: {}", self.filter_text)
        };
        let bar = Paragraph::new(text).style(style);
        f.render_widget(bar, area);
    }

    fn draw_packet_list(&mut self, f: &mut Frame, area: Rect) {
        let highlight_style = if self.active_pane == Pane::PacketList {
            Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD)
        } else {
            Style::default().bg(Color::DarkGray)
        };

        let header = Row::new(vec![
            Cell::from("No."),
            Cell::from("Time"),
            Cell::from("Source"),
            Cell::from("Destination"),
            Cell::from("Protocol"),
            Cell::from("Length"),
            Cell::from("Info"),
        ])
        .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));

        let rows: Vec<Row> = self.filtered_indices.iter().map(|&i| {
            let pkt = &self.packets[i];
            let tree = &pkt.tree;
            let top_proto = &tree.top_protocol;

            // Extract source/destination from IP layer
            let (src, dst) = self.extract_addresses(tree);

            // Get info from the topmost layer
            let info = tree.layers.last()
                .map(|l| l.summary.clone())
                .unwrap_or_default();

            let proto_style = match top_proto.as_str() {
                "TCP" => Style::default().fg(Color::Cyan),
                "UDP" => Style::default().fg(Color::Green),
                "TLS" => Style::default().fg(Color::Magenta),
                "DNS" => Style::default().fg(Color::Blue),
                "HTTP" => Style::default().fg(Color::Red),
                _ => Style::default(),
            };

            Row::new(vec![
                Cell::from(format!("{}", pkt.index + 1)),
                Cell::from(format!("{}", pkt.packet.timestamp)),
                Cell::from(src),
                Cell::from(dst),
                Cell::from(top_proto.clone()).style(proto_style),
                Cell::from(format!("{}", pkt.packet.data.len())),
                Cell::from(info),
            ])
        }).collect();

        let table = Table::new(rows, [
            Constraint::Length(6),
            Constraint::Length(18),
            Constraint::Length(18),
            Constraint::Length(18),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Min(20),
        ])
        .header(header)
        .block(Block::default()
            .title(format!(" Packets ({}/{}) ", self.filtered_indices.len(), self.packets.len()))
            .borders(Borders::ALL)
            .border_style(if self.active_pane == Pane::PacketList {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default()
            }))
        .highlight_style(highlight_style);

        f.render_stateful_widget(table, area, &mut self.packet_table_state);
    }

    fn draw_protocol_tree(&mut self, f: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = if let Some(idx) = self.selected_packet {
            if let Some(&packet_idx) = self.filtered_indices.get(idx) {
                let tree = &self.packets[packet_idx].tree;
                tree.layers.iter().enumerate().flat_map(|(depth, layer)| {
                    let mut items = Vec::new();
                    let indent = "  ".repeat(depth);
                    items.push(ListItem::new(Line::from(vec![
                        Span::styled(
                            format!("{indent}▶ {}", layer.protocol),
                            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                        ),
                    ])));
                    for field in &layer.fields {
                        items.push(ListItem::new(Line::from(vec![
                            Span::raw(format!("{indent}    ")),
                            Span::styled(&field.name, Style::default().fg(Color::Yellow)),
                            Span::raw(": "),
                            Span::styled(&field.display_value, Style::default().fg(Color::White)),
                        ])));
                    }
                    items
                }).collect()
            } else {
                vec![]
            }
        } else {
            vec![ListItem::new("No packet selected")]
        };

        let list = List::new(items)
            .block(Block::default()
                .title(" Protocol Tree ")
                .borders(Borders::ALL)
                .border_style(if self.active_pane == Pane::ProtocolTree {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default()
                }))
            .highlight_style(Style::default().bg(Color::DarkGray));

        f.render_stateful_widget(list, area, &mut self.tree_list_state);
    }

    fn draw_hex_dump(&self, f: &mut Frame, area: Rect) {
        let text = if let Some(idx) = self.selected_packet {
            if let Some(&packet_idx) = self.filtered_indices.get(idx) {
                let data = &self.packets[packet_idx].packet.data;
                model::hex_dump(data, 0)
            } else {
                String::from("No data")
            }
        } else {
            String::from("No packet selected")
        };

        let paragraph = Paragraph::new(text)
            .block(Block::default()
                .title(" Hex Dump ")
                .borders(Borders::ALL)
                .border_style(if self.active_pane == Pane::HexDump {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default()
                }))
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(Color::Green));

        f.render_widget(paragraph, area);
    }

    fn extract_addresses(&self, tree: &DissectionTree) -> (String, String) {
        for layer in &tree.layers {
            if layer.protocol == "IPv4" || layer.protocol == "IPv6" {
                let src = layer.fields.iter()
                    .find(|f| f.name == "Source")
                    .map(|f| f.display_value.clone())
                    .unwrap_or_else(|| "?".into());
                let dst = layer.fields.iter()
                    .find(|f| f.name == "Destination")
                    .map(|f| f.display_value.clone())
                    .unwrap_or_else(|| "?".into());
                return (src, dst);
            }
        }
        // Fall back to Ethernet MAC addresses
        for layer in &tree.layers {
            if layer.protocol == "Ethernet" {
                let src = layer.fields.iter()
                    .find(|f| f.name == "Source")
                    .map(|f| f.display_value.clone())
                    .unwrap_or_else(|| "?".into());
                let dst = layer.fields.iter()
                    .find(|f| f.name == "Destination")
                    .map(|f| f.display_value.clone())
                    .unwrap_or_else(|| "?".into());
                return (src, dst);
            }
        }
        ("?".into(), "?".into())
    }

    fn handle_key(&mut self, key: KeyEvent) {
        if self.filter_editing {
            match key.code {
                KeyCode::Esc => {
                    self.filter_editing = false;
                }
                KeyCode::Enter => {
                    self.filter_editing = false;
                    self.apply_filter();
                }
                KeyCode::Backspace => {
                    self.filter_text.pop();
                }
                KeyCode::Char(c) => {
                    self.filter_text.push(c);
                }
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.should_quit = true;
            }
            KeyCode::Char('/') => {
                self.filter_editing = true;
            }
            KeyCode::Tab => {
                self.active_pane = match self.active_pane {
                    Pane::PacketList => Pane::ProtocolTree,
                    Pane::ProtocolTree => Pane::HexDump,
                    Pane::HexDump => Pane::PacketList,
                };
            }
            KeyCode::Char('j') | KeyCode::Down => self.move_selection(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_selection(-1),
            KeyCode::Char('g') => {
                if self.active_pane == Pane::PacketList && !self.filtered_indices.is_empty() {
                    self.packet_table_state.select(Some(0));
                    self.selected_packet = Some(0);
                }
            }
            KeyCode::Char('G') => {
                if self.active_pane == Pane::PacketList && !self.filtered_indices.is_empty() {
                    let last = self.filtered_indices.len() - 1;
                    self.packet_table_state.select(Some(last));
                    self.selected_packet = Some(last);
                }
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
            }
            _ => {}
        }
    }

    fn move_selection(&mut self, delta: i32) {
        match self.active_pane {
            Pane::PacketList => {
                if self.filtered_indices.is_empty() {
                    return;
                }
                let current = self.packet_table_state.selected().unwrap_or(0);
                let new = if delta > 0 {
                    (current + delta as usize).min(self.filtered_indices.len() - 1)
                } else {
                    current.saturating_sub((-delta) as usize)
                };
                self.packet_table_state.select(Some(new));
                self.selected_packet = Some(new);
            }
            Pane::ProtocolTree => {
                let current = self.tree_list_state.selected().unwrap_or(0);
                let new = if delta > 0 {
                    current.saturating_add(delta as usize)
                } else {
                    current.saturating_sub((-delta) as usize)
                };
                self.tree_list_state.select(Some(new));
            }
            Pane::HexDump => {
                // Hex dump scrolling could be added here
            }
        }
    }

    fn apply_filter(&mut self) {
        if self.filter_text.is_empty() {
            self.filtered_indices = (0..self.packets.len()).collect();
        } else {
            let filter_lower = self.filter_text.to_lowercase();
            self.filtered_indices = self.packets.iter().enumerate()
                .filter(|(_, pkt)| {
                    // Simple text-based filter matching protocol name or summary
                    let tree = &pkt.tree;
                    tree.top_protocol.to_lowercase().contains(&filter_lower)
                        || tree.layers.iter().any(|l| {
                            l.protocol.to_lowercase().contains(&filter_lower)
                            || l.summary.to_lowercase().contains(&filter_lower)
                            || l.fields.iter().any(|f|
                                f.display_value.to_lowercase().contains(&filter_lower)
                            )
                        })
                })
                .map(|(i, _)| i)
                .collect();
        }

        // Reset selection
        if !self.filtered_indices.is_empty() {
            self.packet_table_state.select(Some(0));
            self.selected_packet = Some(0);
        } else {
            self.packet_table_state.select(None);
            self.selected_packet = None;
        }
    }
}
