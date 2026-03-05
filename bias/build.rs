use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::path::Path;

use proc_macro2::{Span, TokenStream};
use quote::{quote, ToTokens, TokenStreamExt};
use serde::Deserialize;
use syn::Ident;

#[derive(Deserialize)]
struct PropertyMetadata {
    name: String,
    constant: String,
    #[serde(default)]
    namespace: Option<String>,
}

enum PropertyOrModule {
    M(PropertyMap),
    P(String),
}

impl ToTokens for PropertyOrModule {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            Self::M(m) => m.to_tokens(tokens),
            Self::P(s) => s.to_tokens(tokens),
        }
    }
}

impl ToTokens for PropertyMap {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        for (k, v) in self.0.iter() {
            let k = Ident::new(k, Span::call_site());
            tokens.append_all(match v {
                PropertyOrModule::M(mm) => {
                    quote! {
                        pub mod #k {
                            #mm
                        }
                    }
                }
                PropertyOrModule::P(p) => {
                    quote! {
                        pub const #k: &'static str = #p;
                    }
                }
            });
        }
    }
}

#[derive(Default)]
struct PropertyMap(BTreeMap<String, PropertyOrModule>);

impl PropertyMap {
    fn add_property(&mut self, p: PropertyMetadata) {
        match p.namespace {
            None => {
                assert!(
                    self.0
                        .insert(p.constant, PropertyOrModule::P(p.name))
                        .is_none(),
                    "propery does not duplicate other property or module name"
                )
            }
            Some(path) => {
                let mut m = &mut self.0;

                for part in path.split('/') {
                    let PropertyOrModule::M(me) = m
                        .entry(part.to_owned())
                        .or_insert_with(|| PropertyOrModule::M(Default::default()))
                    else {
                        panic!("property cannot have same name as module")
                    };
                    m = &mut me.0;
                }

                assert!(
                    m.insert(p.constant, PropertyOrModule::P(p.name)).is_none(),
                    "propery does not duplicate other property or module name"
                );
            }
        }
    }
}

fn build_properties(output: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
    let properties = serde_yaml::from_reader::<_, Vec<PropertyMetadata>>(File::open(
        "meta/properties.yml",
    )?)?;

    let mut mapping = PropertyMap::default();
    for property in properties {
        mapping.add_property(property);
    }

    let tokens = mapping.into_token_stream();
    let content = tokens.to_string();
    let pretty = prettyplease::unparse(&syn::parse_file(&content).expect("valid rust"));

    fs::write(output, pretty).expect("write generated properties");

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    build_properties(
        Path::new(&env::var("OUT_DIR").expect("OUT_DIR set")).join("properties.generated.rs"),
    )?;
    Ok(())
}
