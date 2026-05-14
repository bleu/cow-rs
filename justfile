fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all-targets --all-features --workspace -- -Dwarnings

build:
	cargo build --all-targets --all-features --workspace

test:
	cargo test --all-targets --all-features --workspace

wasm-check:
	cargo check --target wasm32-unknown-unknown --all-features --workspace

# Build the in-browser e2e harness wasm package (requires wasm-pack).
wasm-build:
	cd crates/cow-rs-wasm && wasm-pack build --target web --dev

# Build the harness then serve the workspace so test-harness/index.html
# can resolve the wasm package via relative ES-module imports.
wasm-harness: wasm-build
	@echo "Open http://localhost:8765/test-harness/"
	python3 -m http.server 8765

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features

deny:
	cargo deny check

audit:
	cargo audit --deny warnings
