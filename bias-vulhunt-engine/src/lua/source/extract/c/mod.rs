use super::languages::{Language, Node, TreeCursor};
use super::EntityExtractor;

pub use tree_sitter_c as language;

#[derive(Default)]
pub struct FunctionDefinition {
    name: String,
}

impl FunctionDefinition {
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl<'t> EntityExtractor<'t> for FunctionDefinition {
    const NODE: &'static str = "function_definition";
    const NAMED: bool = true;

    type Target = Self;

    fn extract<'a>(
        &self,
        node: Node<'a>,
        walker: &mut TreeCursor<'a>,
        source: &'a str,
    ) -> Option<Self::Target> {
        let declarator_id = node.language().field_id_for_name("declarator")?;
        let identifier_id = node.language().id_for_node_kind("identifier", true);

        let mut declarator = node.child_by_field_id(declarator_id.into())?;
        let mut identifier = declarator.child_by_field_id(declarator_id.into())?;

        while identifier.kind_id() != identifier_id {
            declarator = identifier.children(walker).find(|child| {
                child.kind_id() == identifier_id || child.kind().ends_with("declarator")
            })?;

            if declarator.kind_id() == identifier_id {
                identifier = declarator;
                break;
            }

            identifier = declarator.child_by_field_id(declarator_id.into())?;
        }

        let name = identifier.utf8_text(source.as_ref()).ok()?.to_owned();

        Some(Self { name })
    }

    fn language(&self) -> Language {
        language::LANGUAGE.into()
    }
}

#[cfg(test)]
mod test {
    use super::super::Extractor;
    use super::*;

    #[test]
    fn test_noop() -> Result<(), anyhow::Error> {
        #[allow(unused)]
        struct BorrowTest<'a> {
            t: &'a i32,
        }

        impl<'t> EntityExtractor<'t> for BorrowTest<'t> {
            const NODE: &'static str = "function_definition";
            const NAMED: bool = true;

            type Target = FunctionDefinition;

            fn extract<'a>(
                &self,
                node: Node<'a>,
                walker: &mut TreeCursor<'a>,
                source: &'a str,
            ) -> Option<Self::Target> {
                let declarator_id = node.language().field_id_for_name("declarator")?;
                let identifier_id = node.language().id_for_node_kind("identifier", true);

                let mut declarator = node.child_by_field_id(declarator_id.into())?;
                let mut identifier = declarator.child_by_field_id(declarator_id.into())?;

                while identifier.kind_id() != identifier_id {
                    declarator = identifier.children(walker).find(|child| {
                        child.kind_id() == identifier_id || child.kind().ends_with("declarator")
                    })?;

                    if declarator.kind_id() == identifier_id {
                        break;
                    }

                    identifier = declarator.child_by_field_id(declarator_id.into())?;
                }

                let name = identifier.utf8_text(source.as_ref()).ok()?.to_owned();

                Some(Self::Target { name })
            }

            fn language(&self) -> Language {
                tree_sitter_c::LANGUAGE.into()
            }
        }

        let t = 10;
        let mut parser = Extractor::new_with(BorrowTest { t: &t })?;
        let source = "void blah(void) { return }\n\nEFI_STATUS EFIAPI foo(EFI_BOOT_SERVICES *bs) { return 0; }";

        let entities = parser.extract(source)?;

        assert_eq!(entities.len(), 2);

        Ok(())
    }

    #[test]
    fn test_extract() -> Result<(), anyhow::Error> {
        let mut parser = Extractor::<FunctionDefinition>::new()?;
        let source = "void blah(void) { return }\n\nEFI_STATUS EFIAPI foo(EFI_BOOT_SERVICES *bs) { return 0; }";

        let entities = parser.extract(source)?;

        assert_eq!(entities.len(), 2);

        assert!(entities
            .iter()
            .find(|entity| entity.data().name() == "blah")
            .is_some());

        assert!(entities
            .iter()
            .find(|entity| entity.data().name() == "foo")
            .is_some());

        Ok(())
    }

    #[test]
    fn test_extract_openssl() -> Result<(), anyhow::Error> {
        let mut parser = Extractor::<FunctionDefinition>::new()?;
        let source = r"
STACK_OF(PKCS12_SAFEBAG) *PKCS12_unpack_p7data(PKCS7 *p7)
{
    if (!PKCS7_type_is_data(p7)) {
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_CONTENT_TYPE_NOT_DATA);
        return NULL;
    }

    if (p7->d.data == NULL) {
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_DECODE_ERROR);
        return NULL;
    }

    return ASN1_item_unpack(p7->d.data, ASN1_ITEM_rptr(PKCS12_SAFEBAGS));
}
";

        let entities = parser.extract(source)?;

        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].data().name(), "PKCS12_unpack_p7data");

        Ok(())
    }
}
