# Format, lint, and type-check
check:
    cargo fmt --check
    cargo clippy --all-targets
    cargo check --all-targets

# Auto-format code
fmt:
    cargo fmt

# Run unit tests (uses nextest if available)
unit:
    @if cargo nextest --version >/dev/null 2>&1; then \
        cargo nextest run; \
    else \
        cargo test; \
    fi

# Run cross-language interop tests (requires python3, go)
interop:
    cargo test --test interop_python -- --ignored
    cargo test --test interop_go -- --ignored

# Run all tests
test-all: unit interop

# Full CI check (format, lint, test)
ci: check unit

# Run Kani formal verification proofs (install: cargo install --locked kani-verifier && cargo kani setup)
kani:
    cargo kani

# Run a specific Kani proof by name
kani-proof name:
    cargo kani --harness {{name}}

# List available Kani proofs
kani-list:
    cargo kani list

# Clean build artifacts
clean:
    cargo clean
