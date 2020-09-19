extern crate proc_macro;
use quote::quote;
use syn::parse_macro_input;
use syn::ItemFn;

use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn test_case(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let f = parse_macro_input!(input as ItemFn);
    let f_ident = &f.sig.ident;
    let q = quote!(
        #f

        inventory::submit!(
            test_utils::TestCase(
                concat!(module_path!(), "::", stringify!(#f_ident)).to_string(),
                #f_ident
            )
        );
    );

    q.into()
}
