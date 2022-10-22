cargo build --release &&
cbindgen --config cbindgen.toml --crate rust-searchable-pke --output ./target/release/rust_searchable_pke.h