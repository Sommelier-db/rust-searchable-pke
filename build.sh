cargo build --release &&
cbindgen --config cbindgen.toml --crate rust-searchable-pke --output rust_apis.h