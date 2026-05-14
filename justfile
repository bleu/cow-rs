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

# Dev build for the in-browser harness (fast, unoptimised). Outputs to
# crates/cow-sdk-wasm/pkg/ which is what test-harness/index.html imports.
wasm-build:
	cd crates/cow-sdk-wasm && wasm-pack build --target web --dev --scope cowdao-grants

# Build the harness then serve the workspace so test-harness/index.html
# can resolve the wasm package via relative ES-module imports.
wasm-harness: wasm-build
	@echo "Open http://localhost:8765/test-harness/"
	python3 -m http.server 8765

# Release builds for each wasm-pack target. Each lands in its own
# pkg-* directory so they can coexist; gitignored under pkg*.
#   web      browser ES modules; the harness loads this.
#   bundler  webpack / Vite / Rollup; the default wasm-pack target.
#   nodejs   CommonJS for Node.
wasm-build-web:
	cd crates/cow-sdk-wasm && wasm-pack build --target web --release --scope cowdao-grants --out-dir pkg-web

wasm-build-bundler:
	cd crates/cow-sdk-wasm && wasm-pack build --target bundler --release --scope cowdao-grants --out-dir pkg-bundler

wasm-build-nodejs:
	cd crates/cow-sdk-wasm && wasm-pack build --target nodejs --release --scope cowdao-grants --out-dir pkg-nodejs

# Build all three release targets, then print the .wasm sizes
# (post-wasm-opt) so size regressions are visible at a glance.
wasm-build-all: wasm-build-web wasm-build-bundler wasm-build-nodejs

wasm-size: wasm-build-all
	@echo ""
	@echo "wasm output sizes (post wasm-opt):"
	@du -h crates/cow-sdk-wasm/pkg-web/*_bg.wasm
	@du -h crates/cow-sdk-wasm/pkg-bundler/*_bg.wasm
	@du -h crates/cow-sdk-wasm/pkg-nodejs/*_bg.wasm

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features

deny:
	cargo deny check

audit:
	cargo audit --deny warnings
