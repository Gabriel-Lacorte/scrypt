# justfile for $crypt framework

default: check

# Build the entire workspace
build:
    cargo build --workspace

# Build in release mode
release:
    cargo build --workspace --release

# Run all tests
test:
    cargo test --workspace

# Run tests for a single crate
test-crate crate:
    cargo test -p {{crate}}

# Check compilation without producing artifacts
check:
    cargo check --workspace

# Run clippy lints
lint:
    cargo clippy --workspace -- -D warnings

# Format all code
fmt:
    cargo fmt --all

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Run the CLI tool
run *args:
    cargo run --bin scrypt -- {{args}}

# Analyze a PCAP file
analyze file:
    cargo run --bin scrypt -- analyze --input {{file}}

# Open TUI with a PCAP file
tui file:
    cargo run --bin scrypt -- tui --input {{file}}

# Clean build artifacts
clean:
    cargo clean

# Show system info
info:
    cargo run --bin scrypt -- info
