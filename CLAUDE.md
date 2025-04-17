# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build/Lint/Test Commands
- Build: `cargo build`
- Run: `cargo run`
- Check: `cargo check`
- Test (all): `cargo test`
- Test (single): `cargo test test_name`
- Format: `cargo fmt`
- Lint: `cargo clippy`

## Code Style Guidelines
- **Imports**: Group imports by external crates first, then internal modules
- **Formatting**: Follow Rust style guide with 4-space indentation
- **Types**: Use strong typing and leverage Rust's type system
- **Error Handling**: Use Result for error propagation, avoid unwrap() in production code
- **Documentation**: Document public functions with /// comments
- **Naming**: Use snake_case for variables/functions, CamelCase for types
- **Comments**: Only add comments for non-obvious logic
- **Code Organization**: Follow the Rust module system, keep files focused on a single purpose