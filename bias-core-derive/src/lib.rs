extern crate proc_macro;

mod any_lifetime;

use proc_macro::TokenStream;

#[proc_macro_derive(ProvidesStaticType)]
pub fn derive_provides_static_type(input: TokenStream) -> TokenStream {
    any_lifetime::derive_provides_static_type(input)
}
