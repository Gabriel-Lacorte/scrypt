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
    widgets::{Block, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Table, TableState},
    Frame, Terminal,
};
use sc_pcap::AnalyzedPacket;
use sc_protocol::DissectionTree;
use std::io;

/// Color theme for the TUI.
#[derive(Debug, Clone)]
pub struct Theme {
    pub border_active: Color,
    pub border_inactive: Color,
    pub header_fg: Color,
    pub highlight_bg: Color,
    pub filter_active_fg: Color,
    pub filter_inactive_fg: Color,
    pub hex_fg: Color,
    pub status_fg: Color,
    pub status_bg: Color,
    pub proto_tcp: Color,
    pub proto_udp: Color,
    pub proto_tls: Color,
    pub proto_dns: Color,
    pub proto_http: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            border_active: Color::Cyan,
            border_inactive: Color::DarkGray,
            header_fg: Color::Yellow,
            highlight_bg: Color::DarkGray,
            filter_active_fg: Color::Yellow,
            filter_inactive_fg: Color::DarkGray,
            hex_fg: Color::Green,
            status_fg: Color::White,
            status_bg: Color::DarkGray,
            proto_tcp: Color::Cyan,
            proto_udp: Color::Green,
            proto_tls: Color::Magenta,
            proto_dns: Color::Blue,
            proto_http: Color::Red,
        }
    }
}

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
    /// Hex dump scroll offset (line-based)
    hex_scroll: u16,
    /// Color theme
    theme: Theme,
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
            hex_scroll: 0,
            theme: Theme::default(),
            should_quit: false,
        }
    }

    /// Create an App with a custom theme.
    pub fn with_theme(mut self, theme: Theme) -> Self {
        self.theme = theme;
        self
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

        // Main layout: filter bar / packet list / bottom panes / status bar
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),      // Filter bar
                Constraint::Percentage(40), // Packet list
                Constraint::Percentage(55), // Bottom panes
                Constraint::Length(1),      // Status bar
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
        self.draw_status_bar(f, main_chunks[3]);
    }

    fn draw_filter_bar(&self, f: &mut Frame, area: Rect) {
        let style = if self.filter_editing {
            Style::default().fg(self.theme.filter_active_fg)
        } else {
            Style::default().fg(self.theme.filter_inactive_fg)
        };
        let text = if self.filter_text.is_empty() {
            "Press / to filter (e.g. tcp, udp, ip.src==10.0.0.1, port:443)...".to_string()
        } else {
            format!("Filter: {}", self.filter_text)
        };
        let bar = Paragraph::new(text).style(style);
        f.render_widget(bar, area);
    }

    fn draw_packet_list(&mut self, f: &mut Frame, area: Rect) {
        let highlight_style = if self.active_pane == Pane::PacketList {
            Style::default()
                .bg(self.theme.highlight_bg)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().bg(self.theme.highlight_bg)
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
        .style(
            Style::default()
                .fg(self.theme.header_fg)
                .add_modifier(Modifier::BOLD),
        );

        let theme = &self.theme;
        let rows: Vec<Row> = self
            .filtered_indices
            .iter()
            .map(|&i| {
                let pkt = &self.packets[i];
                let tree = &pkt.tree;
                let top_proto = &tree.top_protocol;

                let (src, dst) = extract_addresses(tree);

                let info = tree
                    .layers
                    .last()
                    .map(|l| l.summary.clone())
                    .unwrap_or_default();

                let proto_style = match top_proto.as_str() {
                    "TCP" => Style::default().fg(theme.proto_tcp),
                    "UDP" => Style::default().fg(theme.proto_udp),
                    "TLS" => Style::default().fg(theme.proto_tls),
                    "DNS" => Style::default().fg(theme.proto_dns),
                    "HTTP" => Style::default().fg(theme.proto_http),
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
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Length(6),
                Constraint::Length(18),
                Constraint::Length(18),
                Constraint::Length(18),
                Constraint::Length(8),
                Constraint::Length(6),
                Constraint::Min(20),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .title(format!(
                    " Packets ({}/{}) ",
                    self.filtered_indices.len(),
                    self.packets.len()
                ))
                .borders(Borders::ALL)
                .border_style(if self.active_pane == Pane::PacketList {
                    Style::default().fg(self.theme.border_active)
                } else {
                    Style::default().fg(self.theme.border_inactive)
                }),
        )
        .row_highlight_style(highlight_style);

        f.render_stateful_widget(table, area, &mut self.packet_table_state);
    }

    fn draw_protocol_tree(&mut self, f: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = if let Some(idx) = self.selected_packet {
            if let Some(&packet_idx) = self.filtered_indices.get(idx) {
                let tree = &self.packets[packet_idx].tree;
                tree.layers
                    .iter()
                    .enumerate()
                    .flat_map(|(depth, layer)| {
                        let mut items = Vec::new();
                        let indent = "  ".repeat(depth);
                        items.push(ListItem::new(Line::from(vec![Span::styled(
                            format!("{indent}> {}", layer.protocol),
                            Style::default()
                                .fg(self.theme.border_active)
                                .add_modifier(Modifier::BOLD),
                        )])));
                        for field in &layer.fields {
                            items.push(ListItem::new(Line::from(vec![
                                Span::raw(format!("{indent}    ")),
                                Span::styled(
                                    &field.name,
                                    Style::default().fg(self.theme.header_fg),
                                ),
                                Span::raw(": "),
                                Span::styled(
                                    &field.display_value,
                                    Style::default().fg(Color::White),
                                ),
                            ])));
                        }
                        items
                    })
                    .collect()
            } else {
                vec![]
            }
        } else {
            vec![ListItem::new("No packet selected")]
        };

        let list = List::new(items)
            .block(
                Block::default()
                    .title(" Protocol Tree ")
                    .borders(Borders::ALL)
                    .border_style(if self.active_pane == Pane::ProtocolTree {
                        Style::default().fg(self.theme.border_active)
                    } else {
                        Style::default().fg(self.theme.border_inactive)
                    }),
            )
            .highlight_style(Style::default().bg(self.theme.highlight_bg));

        f.render_stateful_widget(list, area, &mut self.tree_list_state);
    }

    fn draw_hex_dump(&self, f: &mut Frame, area: Rect) {
        let inner_width = area.width.saturating_sub(2) as usize; // minus borders
        let text = if let Some(idx) = self.selected_packet {
            if let Some(&packet_idx) = self.filtered_indices.get(idx) {
                let data = &self.packets[packet_idx].packet.data;
                format_hex_dump(data, inner_width)
            } else {
                String::from("No data")
            }
        } else {
            String::from("No packet selected")
        };

        let paragraph = Paragraph::new(text)
            .block(
                Block::default()
                    .title(" Hex Dump ")
                    .borders(Borders::ALL)
                    .border_style(if self.active_pane == Pane::HexDump {
                        Style::default().fg(self.theme.border_active)
                    } else {
                        Style::default().fg(self.theme.border_inactive)
                    }),
            )
            .scroll((self.hex_scroll, 0))
            .style(Style::default().fg(self.theme.hex_fg));

        f.render_widget(paragraph, area);
    }

    fn draw_status_bar(&self, f: &mut Frame, area: Rect) {
        let pane_name = match self.active_pane {
            Pane::PacketList => "Packet List",
            Pane::ProtocolTree => "Protocol Tree",
            Pane::HexDump => "Hex Dump",
        };
        let pkt_info = if let Some(idx) = self.selected_packet {
            format!("Packet {}/{}", idx + 1, self.filtered_indices.len())
        } else {
            "No selection".into()
        };
        let status = format!(
            " [{pane_name}] | {pkt_info} | Total: {} | q:Quit /:Filter Tab:Switch j/k:Navigate g/G:Top/Bottom",
            self.packets.len()
        );
        let bar = Paragraph::new(status).style(
            Style::default()
                .fg(self.theme.status_fg)
                .bg(self.theme.status_bg),
        );
        f.render_widget(bar, area);
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
            KeyCode::Char('g') => match self.active_pane {
                Pane::PacketList if !self.filtered_indices.is_empty() => {
                    self.packet_table_state.select(Some(0));
                    self.selected_packet = Some(0);
                    self.hex_scroll = 0;
                }
                Pane::HexDump => {
                    self.hex_scroll = 0;
                }
                _ => {}
            },
            KeyCode::Char('G') => {
                match self.active_pane {
                    Pane::PacketList if !self.filtered_indices.is_empty() => {
                        let last = self.filtered_indices.len() - 1;
                        self.packet_table_state.select(Some(last));
                        self.selected_packet = Some(last);
                    }
                    Pane::HexDump => {
                        // Scroll to bottom
                        self.hex_scroll = self.hex_dump_max_scroll();
                    }
                    _ => {}
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
                self.hex_scroll = 0; // Reset hex scroll on packet change
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
                let max = self.hex_dump_max_scroll();
                if delta > 0 {
                    self.hex_scroll = (self.hex_scroll + delta as u16).min(max);
                } else {
                    self.hex_scroll = self.hex_scroll.saturating_sub((-delta) as u16);
                }
            }
        }
    }

    /// Compute max scroll offset for hex dump (one line per 16 bytes).
    fn hex_dump_max_scroll(&self) -> u16 {
        if let Some(idx) = self.selected_packet {
            if let Some(&packet_idx) = self.filtered_indices.get(idx) {
                let len = self.packets[packet_idx].packet.data.len();
                let lines = len.div_ceil(16);
                return lines.saturating_sub(1) as u16;
            }
        }
        0
    }

    fn apply_filter(&mut self) {
        if self.filter_text.is_empty() {
            self.filtered_indices = (0..self.packets.len()).collect();
        } else {
            let expr = self.filter_text.trim().to_lowercase();
            self.filtered_indices = self
                .packets
                .iter()
                .enumerate()
                .filter(|(_, pkt)| filter_matches(pkt, &expr))
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
        self.hex_scroll = 0;
    }
}

/// Extract source/destination addresses from a dissection tree.
fn extract_addresses(tree: &DissectionTree) -> (String, String) {
    for layer in &tree.layers {
        if layer.protocol == "IPv4" || layer.protocol == "IPv6" {
            let src = layer
                .fields
                .iter()
                .find(|f| f.name == "Source")
                .map(|f| f.display_value.clone())
                .unwrap_or_else(|| "?".into());
            let dst = layer
                .fields
                .iter()
                .find(|f| f.name == "Destination")
                .map(|f| f.display_value.clone())
                .unwrap_or_else(|| "?".into());
            return (src, dst);
        }
    }
    for layer in &tree.layers {
        if layer.protocol == "Ethernet" {
            let src = layer
                .fields
                .iter()
                .find(|f| f.name == "Source")
                .map(|f| f.display_value.clone())
                .unwrap_or_else(|| "?".into());
            let dst = layer
                .fields
                .iter()
                .find(|f| f.name == "Destination")
                .map(|f| f.display_value.clone())
                .unwrap_or_else(|| "?".into());
            return (src, dst);
        }
    }
    ("?".into(), "?".into())
}

/// Generate a hex dump string adapted to the available `width` (in columns).
///
/// Dynamically picks the largest bytes-per-line (multiple of 4, max 16) that fits.
/// Each line: `OFFSET  HH HH ...  |ASCII...|`
fn format_hex_dump(data: &[u8], width: usize) -> String {
    if data.is_empty() {
        return String::from("(empty)");
    }

    // For N bytes per line (no mid-gap):  10 + 3*N + 2 + N + 1 = 13 + 4*N
    // With mid-gap (added when N > 8):    14 + 4*N
    // Solve for N: N = (width - 13) / 4  (or (width - 14) / 4 if mid-gap)
    // Round down to nearest multiple of 4, clamp to [4, 16].
    let max_n = if width >= 14 {
        (width - 14) / 4 // assume mid-gap to be safe
    } else {
        1
    };
    let bpl = (max_n / 4 * 4).clamp(4, 16);
    let use_gap = bpl > 8;

    let mut out = String::new();
    for (i, chunk) in data.chunks(bpl).enumerate() {
        let addr = i * bpl;
        out.push_str(&format!("{addr:08x}  "));

        for (j, byte) in chunk.iter().enumerate() {
            if use_gap && j == bpl / 2 {
                out.push(' ');
            }
            out.push_str(&format!("{byte:02x} "));
        }
        // Pad remaining hex columns
        for j in chunk.len()..bpl {
            if use_gap && j == bpl / 2 {
                out.push(' ');
            }
            out.push_str("   ");
        }

        out.push_str(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                out.push(*byte as char);
            } else {
                out.push('.');
            }
        }
        // Pad ASCII column for incomplete last line
        for _ in chunk.len()..bpl {
            out.push(' ');
        }
        out.push_str("|\n");
    }
    out
}

/// Parse a filter expression like `ip.src==10.0.0.1` or `ip.src == 10.0.0.1`.
/// Returns the trimmed value after the operator, or None if prefix doesn't match.
fn strip_filter_op<'a>(expr: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = expr.strip_prefix(prefix)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix("==")?;
    let rest = rest.trim_start();
    if rest.is_empty() {
        None
    } else {
        Some(rest)
    }
}

/// BPF-style expression filter.
///
/// Supports:
///   - Protocol name: `tcp`, `udp`, `tls`, `dns`, `http`, `ipv4`, `ipv6`
///   - Port filter: `port:443`, `port:80`
///   - IP address filter: `ip.src==10.0.0.1`, `ip.dst==192.168.1.0`
///   - Field value match: `field:value` (searches all field display values)
///   - Fallback: plain text search across protocols, summaries, and fields
fn filter_matches(pkt: &AnalyzedPacket, expr: &str) -> bool {
    let tree = &pkt.tree;

    // Exact protocol match
    if matches!(
        expr,
        "tcp" | "udp" | "tls" | "dns" | "http" | "ipv4" | "ipv6" | "ethernet" | "arp"
    ) {
        let upper = expr.to_uppercase();
        if tree.top_protocol == upper {
            return true;
        }
        return tree
            .layers
            .iter()
            .any(|l| l.protocol.eq_ignore_ascii_case(expr));
    }

    // Port filter: port:NUMBER
    if let Some(port_str) = expr.strip_prefix("port:") {
        if let Ok(port) = port_str.trim().parse::<u16>() {
            let port_s = port.to_string();
            return tree.layers.iter().any(|l| {
                l.fields.iter().any(|f| {
                    (f.name == "Source Port" || f.name == "Destination Port")
                        && f.display_value == port_s
                })
            });
        }
    }

    // IP source filter: ip.src==ADDRESS (tolerates spaces around ==)
    if let Some(addr) = strip_filter_op(expr, "ip.src") {
        return tree.layers.iter().any(|l| {
            (l.protocol == "IPv4" || l.protocol == "IPv6")
                && l.fields
                    .iter()
                    .any(|f| f.name == "Source" && f.display_value == addr)
        });
    }

    // IP destination filter: ip.dst==ADDRESS (tolerates spaces around ==)
    if let Some(addr) = strip_filter_op(expr, "ip.dst") {
        return tree.layers.iter().any(|l| {
            (l.protocol == "IPv4" || l.protocol == "IPv6")
                && l.fields
                    .iter()
                    .any(|f| f.name == "Destination" && f.display_value == addr)
        });
    }

    // Field value search: field:VALUE
    if let Some(val) = expr.strip_prefix("field:") {
        let val = val.trim().to_lowercase();
        return tree.layers.iter().any(|l| {
            l.fields
                .iter()
                .any(|f| f.display_value.to_lowercase().contains(&val))
        });
    }

    // Fallback: plain text search across protocols, summaries, and fields
    tree.top_protocol.to_lowercase().contains(expr)
        || tree.layers.iter().any(|l| {
            l.protocol.to_lowercase().contains(expr)
                || l.summary.to_lowercase().contains(expr)
                || l.fields.iter().any(|f| {
                    f.name.to_lowercase().contains(expr)
                        || f.display_value.to_lowercase().contains(expr)
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sc_core::types::{OwnedPacket, Timestamp};
    use sc_protocol::{DissectionTree, Field, FieldType, ProtocolNode};

    fn make_packet(protocol: &str, fields: Vec<(&str, &str)>) -> AnalyzedPacket {
        let layers = vec![ProtocolNode {
            protocol: protocol.to_string(),
            byte_range: 0..10,
            fields: fields
                .into_iter()
                .map(|(n, v)| Field {
                    name: n.to_string(),
                    display_value: v.to_string(),
                    byte_range: 0..0,
                    field_type: FieldType::String,
                })
                .collect(),
            summary: format!("{protocol} packet"),
        }];
        AnalyzedPacket {
            index: 0,
            packet: OwnedPacket {
                timestamp: Timestamp::new(0, 0),
                data: vec![0u8; 64],
                original_len: 64,
                link_type: 1,
            },
            tree: DissectionTree {
                top_protocol: protocol.to_string(),
                layers,
            },
        }
    }

    #[test]
    fn test_filter_protocol() {
        let pkt = make_packet(
            "TCP",
            vec![("Source Port", "443"), ("Destination Port", "12345")],
        );
        assert!(filter_matches(&pkt, "tcp"));
        assert!(!filter_matches(&pkt, "udp"));
    }

    #[test]
    fn test_filter_port() {
        let pkt = make_packet(
            "TCP",
            vec![("Source Port", "443"), ("Destination Port", "12345")],
        );
        assert!(filter_matches(&pkt, "port:443"));
        assert!(filter_matches(&pkt, "port:12345"));
        assert!(!filter_matches(&pkt, "port:80"));
    }

    #[test]
    fn test_filter_ip() {
        let pkt = make_packet(
            "IPv4",
            vec![("Source", "10.0.0.1"), ("Destination", "192.168.1.1")],
        );
        assert!(filter_matches(&pkt, "ip.src==10.0.0.1"));
        assert!(filter_matches(&pkt, "ip.dst==192.168.1.1"));
        assert!(!filter_matches(&pkt, "ip.src==10.0.0.2"));
        // With spaces around ==
        assert!(filter_matches(&pkt, "ip.src == 10.0.0.1"));
        assert!(filter_matches(&pkt, "ip.dst == 192.168.1.1"));
        assert!(filter_matches(&pkt, "ip.src ==10.0.0.1"));
        assert!(filter_matches(&pkt, "ip.src== 10.0.0.1"));
    }

    #[test]
    fn test_filter_text_fallback() {
        let pkt = make_packet("DNS", vec![("Query", "example.com")]);
        assert!(filter_matches(&pkt, "example"));
    }

    #[test]
    fn test_theme_default() {
        let theme = Theme::default();
        assert_eq!(theme.border_active, Color::Cyan);
    }

    #[test]
    fn test_hex_dump_max_scroll() {
        let pkt = make_packet("TCP", vec![]);
        let app = App::new(vec![pkt]);
        // 64 bytes = 4 lines of 16, max scroll = 3
        assert_eq!(app.hex_dump_max_scroll(), 3);
    }

    #[test]
    fn test_format_hex_dump_wide() {
        let data: Vec<u8> = (0..32).collect();
        let dump = format_hex_dump(&data, 80);
        let lines: Vec<&str> = dump.trim_end().split('\n').collect();
        assert_eq!(lines.len(), 2); // 32 bytes / 16 bpl = 2 lines
                                    // Each line should fit within 80 cols and contain offset + hex + ASCII
        assert!(lines[0].starts_with("00000000"));
        assert!(lines[0].contains('|'));
    }

    #[test]
    fn test_format_hex_dump_narrow() {
        let data: Vec<u8> = (0..32).collect();
        // width 30 → (30-14)/4=4 → bpl=4 → 32/4 = 8 lines
        let dump = format_hex_dump(&data, 30);
        let lines: Vec<&str> = dump.trim_end().split('\n').collect();
        assert_eq!(lines.len(), 8);
    }

    #[test]
    fn test_format_hex_dump_medium() {
        let data: Vec<u8> = (0..48).collect();
        // width 62 → (62-14)/4=12 → bpl=12 → 48/12 = 4 lines
        let dump = format_hex_dump(&data, 62);
        let lines: Vec<&str> = dump.trim_end().split('\n').collect();
        assert_eq!(lines.len(), 4);
    }

    #[test]
    fn test_strip_filter_op() {
        assert_eq!(
            strip_filter_op("ip.src==10.0.0.1", "ip.src"),
            Some("10.0.0.1")
        );
        assert_eq!(
            strip_filter_op("ip.src == 10.0.0.1", "ip.src"),
            Some("10.0.0.1")
        );
        assert_eq!(
            strip_filter_op("ip.src ==10.0.0.1", "ip.src"),
            Some("10.0.0.1")
        );
        assert_eq!(
            strip_filter_op("ip.src== 10.0.0.1", "ip.src"),
            Some("10.0.0.1")
        );
        assert_eq!(strip_filter_op("ip.dst==1.2.3.4", "ip.src"), None);
        assert_eq!(strip_filter_op("ip.src==", "ip.src"), None);
    }
}
