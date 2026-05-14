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

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features
