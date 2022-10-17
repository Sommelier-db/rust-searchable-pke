extern crate libtool;

fn main() {
    libtool::generate_convenience_lib("librust_searchable_pke").unwrap();
}
