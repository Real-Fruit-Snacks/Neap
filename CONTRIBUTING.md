# Contributing to Neap

## Development Setup

1. Install Rust via [rustup](https://rustup.rs/)
2. Clone the repository
3. Run `cargo build` to verify your setup
4. Run `cargo test` to verify tests pass

## Pre-commit Hook

Install the pre-commit hook to automatically check formatting and linting before
each commit:

```bash
cp scripts/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy` and fix all warnings
- No `.unwrap()` in production code — use `?`, `.expect("reason")`, or proper error handling
- Add `// SAFETY:` comments to all `unsafe` blocks

## Pull Request Process

1. Create a feature branch from `main`
2. Write tests for new functionality
3. Ensure `cargo test`, `cargo fmt --check`, and `cargo clippy` all pass
4. Submit a pull request with a clear description of changes

## Reporting Issues

Use GitHub Issues for bug reports and feature requests.

## License

By contributing, you agree that your contributions will be licensed under GPLv3.
