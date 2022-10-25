#[cfg(feature = "la")]
use libtool;
fn main() {
    #[cfg(feature = "la")]
    libtool::generate_convenience_lib("librust_searchable_pke").unwrap();
}
