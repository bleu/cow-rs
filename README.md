# cow-rs

A Rust SDK for the [CoW Protocol](https://cow.fi).

## Status

Early. Currently exposes the canonical signed order payload (`OrderData`) and its EIP-712 struct hash. Parity targets follow [`cowprotocol/cow-sdk`](https://github.com/cowprotocol/cow-sdk) (TypeScript) and [`cowdao-grants/cow-py`](https://github.com/cowdao-grants/cow-py) (Python).

## Layout

```
crates/
  cow-rs/        Library crate. Re-exports the public API.
```

## Building

```
cargo build
cargo test
cargo clippy --all-targets -- -Dwarnings
```

MSRV: 1.93. Edition 2024.

## Licence

GPL-3.0-or-later. See [LICENSE](./LICENSE).
