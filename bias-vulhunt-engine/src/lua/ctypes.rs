use bias_core::fugue::ir::float_format::FloatFormat;
use bias_core::prelude::*;

use crate::lua::source::extract::languages::{Language, Node, TreeCursor};
use crate::lua::source::extract::EntityExtractor;
use crate::lua::source::extract::c::language::LANGUAGE;

use smallvec::SmallVec;
use ustr::Ustr;

#[allow(unused)]
pub struct CDeclarationExtractor<'extract> {
    types: &'extract TypeDB,
    abits: u32,

    declaration: u16,

    array_declarator: u16,
    abstract_array_declarator: u16,

    function_declarator: u16,
    abstract_function_declarator: u16,

    parameter_declarator: u16,

    pointer_declarator: u16,
    abstract_pointer_declarator: u16,

    parenthesised_declarator: u16,
    abstract_parenthesised_declarator: u16,

    struct_specifier: u16,
    primitive_type: u16,

    sized_type_specifier: u16,
    type_identifier: u16,
    identifier: u16,
    number_literal: u16,
}

impl<'extract> CDeclarationExtractor<'extract> {
    pub fn new(project: &'extract Project) -> Self {
        Self::new_with(project.type_db(), project.lifter().address_bits())
    }

    pub fn new_with(types: &'extract TypeDB, address_bits: u32) -> Self {
        let c = Language::from(LANGUAGE);

        let declaration = c.id_for_node_kind("declaration", false);

        let array_declarator = c.id_for_node_kind("array_declarator", true);
        let abstract_array_declarator = c.id_for_node_kind("abstract_pointer_declarator", true);

        let function_declarator = c.id_for_node_kind("function_declarator", true);
        let abstract_function_declarator = c.id_for_node_kind("abstract_function_declarator", true);

        let parameter_declarator = c.id_for_node_kind("parameter_declarator", false);

        let pointer_declarator = c.id_for_node_kind("pointer_declarator", true);
        let abstract_pointer_declarator = c.id_for_node_kind("abstract_pointer_declarator", true);

        let parenthesised_declarator = c.id_for_node_kind("parenthesised_declarator", false);
        let abstract_parenthesised_declarator =
            c.id_for_node_kind("abstract_parenthesised_declarator", false);

        let struct_specifier = c.id_for_node_kind("struct_specifier", true);
        let primitive_type = c.id_for_node_kind("primitive_type", true);

        let sized_type_specifier = c.id_for_node_kind("sized_type_specifier", true);
        let type_identifier = c.id_for_node_kind("type_identifier", true);
        let identifier = c.id_for_node_kind("identifier", true);
        let number_literal = c.id_for_node_kind("number_literal", false);

        Self {
            types,
            abits: address_bits,

            declaration,

            array_declarator,
            abstract_array_declarator,

            function_declarator,
            abstract_function_declarator,

            parameter_declarator,

            pointer_declarator,
            abstract_pointer_declarator,

            parenthesised_declarator,
            abstract_parenthesised_declarator,

            struct_specifier,
            primitive_type,

            sized_type_specifier,
            type_identifier,
            identifier,
            number_literal,
        }
    }

    fn convert_sized<'a>(&self, primitive: Node<'a>, source: &'a str) -> Option<Term<Type>> {
        let sized = primitive.utf8_text(source.as_bytes()).unwrap();
        let parts = sized
            .split(' ')
            .filter(|t| !t.is_empty())
            .collect::<SmallVec<[&str; 3]>>();

        Some(match parts.as_slice() {
            ["unsigned", "char"] => Type::unsigned_char(),
            ["signed", "char"] => Type::char(),

            ["short"] | ["signed", "short"] | ["signed", "short", "int"] | ["short", "int"] => {
                Type::signed(16)
            }
            ["unsigned", "short"] | ["unsigned", "short", "int"] => Type::unsigned(16),

            ["signed"] | ["signed", "int"] => Type::signed(32),
            ["unsigned"] | ["unsigned", "int"] => Type::unsigned(32),

            ["long"] | ["signed", "long"] | ["signed", "long", "int"] | ["long", "int"] => {
                Type::signed(self.abits)
            }

            ["unsigned", "long"] | ["unsigned", "long", "int"] => Type::unsigned(self.abits),

            ["long", "double"] => Type::float(FloatFormat::float16()),

            _ => return None,
        })
    }

    fn convert_primitive<'a>(&self, primitive: Node<'a>, source: &'a str) -> Option<Term<Type>> {
        Some(match primitive.utf8_text(source.as_bytes()).unwrap() {
            "void" => Type::void(),
            "bool" => Type::bool(),
            "char" => Type::char(),

            "uint8_t" | "char8_t" => Type::unsigned(8),
            "uint16_t" | "char16_t" => Type::unsigned(16),
            "uint32_t" | "char32_t" => Type::unsigned(32),
            "uint64_t" | "char64_t" => Type::unsigned(64),

            "int8_t" => Type::signed(8),
            "int16_t" => Type::signed(16),
            "int32_t" => Type::signed(32),
            "int64_t" => Type::signed(64),

            "int" => Type::signed(32),

            "float" => Type::float(FloatFormat::float4()),
            "double" => Type::float(FloatFormat::float8()),

            "size_t" | "uintptr_t" => Type::unsigned(self.abits),
            "ssize_t" | "ptrdiff_t" | "intptr_t" => Type::signed(self.abits),
            "max_align_t" => Type::unsigned(self.abits * 2),
            "nullptr_t" => Type::pointer(Type::void(), self.abits),
            "charptr_t" => Type::pointer(Type::char(), self.abits),

            _ => return None,
        })
    }

    fn convert_named<'a>(&self, named: Node<'a>, source: &'a str) -> Option<Term<Type>> {
        let name = named.utf8_text(source.as_bytes()).unwrap();
        self.types.get_typedef_for(name, self.abits)
    }

    fn convert_type<'a>(&self, t: Node<'a>, source: &'a str) -> Option<Term<Type>> {
        let tkind = t.kind_id();

        if tkind == self.primitive_type {
            self.convert_primitive(t, source)
        } else if tkind == self.sized_type_specifier {
            self.convert_sized(t, source)
        } else if tkind == self.struct_specifier {
            let name = t.child_by_field_name("name")?;
            self.convert_named(name, source)
        } else if tkind == self.type_identifier {
            self.convert_named(t, source)
        } else {
            // not supported yet..
            None
        }
    }

    fn convert_decl<'a>(
        &self,
        t: Term<Type>,
        d: Node<'a>,
        source: &'a str,
    ) -> Option<(Option<&'a str>, Term<Type>)> {
        let dkind = d.kind_id();
        let dd = d.child_by_field_name("declarator");

        let tt = if dkind == self.pointer_declarator {
            Type::pointer(t, self.abits)
        } else if dkind == self.array_declarator || dkind == self.abstract_parenthesised_declarator
        {
            if let Some(size) = d.child_by_field_name("size") {
                let count = size
                    .utf8_text(source.as_bytes())
                    .unwrap()
                    .parse::<u32>()
                    .ok()?;
                if count == 0 {
                    // treat it as a pointer
                    Type::pointer(t, self.abits)
                } else {
                    Type::array(t, count)
                }
            } else {
                // treat it as a pointer
                Type::pointer(t, self.abits)
            }
        } else if dkind == self.function_declarator || dkind == self.abstract_function_declarator {
            // NOTE:
            // - t will be the return type
            // - we parse the current type: args + return then push that into d

            let mut fargs = Vec::new();

            let params = d.child_by_field_name("parameters")?;

            let mut params_walker = params.walk();
            let params_iter = params.named_children(&mut params_walker);

            for param in params_iter {
                let ptype = param.child_by_field_name("type")?;
                let pdecl = param.child_by_field_name("declarator");

                let (pname, ptype) = self.convert_name_and_type(ptype, pdecl, source)?;

                fargs.push(FunctionArg::new(pname.map(Ustr::from), ptype));
            }

            Type::function(t, fargs.into_iter())
        } else if dkind == self.identifier {
            // we reached the end!
            return Some((Some(d.utf8_text(source.as_bytes()).unwrap()), t));
        } else {
            return None;
        };

        if let Some(dd) = dd {
            self.convert_decl(tt, dd, source)
        } else {
            Some((None, tt))
        }
    }

    fn convert_name_and_type<'a>(
        &self,
        ttype: Node<'a>,
        tdecl: impl Into<Option<Node<'a>>>,
        source: &'a str,
    ) -> Option<(Option<&'a str>, Term<Type>)> {
        let tdecl = tdecl.into();
        let ttype = self.convert_type(ttype, source)?;

        if let Some(tdecl) = tdecl {
            self.convert_decl(ttype, tdecl, source)
        } else {
            Some((None, ttype))
        }
    }
}

impl<'extract> EntityExtractor<'extract> for CDeclarationExtractor<'extract> {
    const NODE: &'static str = "declaration";
    const NAMED: bool = true;

    type Target = CDeclaration;

    fn extract<'a>(
        &self,
        node: Node<'a>,
        _walker: &mut TreeCursor<'a>,
        source: &'a str,
    ) -> Option<Self::Target> {
        let dtype = node.child_by_field_name("type")?;
        let ddecl = node.child_by_field_name("declarator")?;

        let (tname, ttype) = self.convert_name_and_type(dtype, ddecl, source)?;

        Some(CDeclaration {
            name: tname.and_then(|n| if n == "_" { None } else { Some(Ustr::from(n)) }),
            type_: ttype,
        })
    }

    fn language(&self) -> Language {
        LANGUAGE.into()
    }
}

pub struct CDeclaration {
    name: Option<Ustr>,
    type_: Term<Type>,
}

impl CDeclaration {
    pub fn name(&self) -> Option<Ustr> {
        self.name
    }

    pub fn type_(&self) -> &Term<Type> {
        &self.type_
    }
}

#[repr(transparent)]
pub struct CPrototypeExtractor<'extract>(CDeclarationExtractor<'extract>);

impl<'extract> CPrototypeExtractor<'extract> {
    pub fn new(project: &'extract Project) -> Self {
        Self::new_with(project.type_db(), project.lifter().address_bits())
    }

    pub fn new_with(types: &'extract TypeDB, address_bits: u32) -> Self {
        Self(CDeclarationExtractor::new_with(types, address_bits))
    }
}

impl<'extract> EntityExtractor<'extract> for CPrototypeExtractor<'extract> {
    const NODE: &'static str = "declaration";
    const NAMED: bool = true;

    type Target = CPrototype;

    fn extract<'a>(
        &self,
        node: Node<'a>,
        _walker: &mut TreeCursor<'a>,
        source: &'a str,
    ) -> Option<Self::Target> {
        let rtype = node.child_by_field_name("type")?;
        let rdecl = node.child_by_field_name("declarator")?;

        let (tname, ttype) = self.0.convert_name_and_type(rtype, rdecl, source)?;

        if ttype.is_function() {
            Some(CPrototype {
                name: tname.and_then(|n| if n == "_" { None } else { Some(Ustr::from(n)) }),
                proto: ttype,
            })
        } else {
            None
        }
    }

    fn language(&self) -> Language {
        LANGUAGE.into()
    }
}

pub struct CPrototype {
    name: Option<Ustr>,
    proto: Term<Type>,
}

impl CPrototype {
    pub fn name(&self) -> Option<Ustr> {
        self.name
    }

    pub fn prototype(&self) -> &Term<Type> {
        &self.proto
    }
}

#[cfg(test)]
mod test {
    use std::env;
    use std::path::Path;

    use super::*;
    use crate::lua::source::extract::*;

    #[test]
    fn test_parse() -> Result<(), Box<dyn std::error::Error>> {
        let data = env::var("BIAS_DATA")?;
        let types = Path::new(&data).join("platforms/uefi/types/edk.h");

        let mut tdb = TypeDB::new();

        tdb.load_file(types)?;

        let mut t = Extractor::new_with(CPrototypeExtractor::new_with(&tdb, 64))?;

        let source = "struct EFI_FILE_INFO *beep_beep(int *b[10], int)";

        let tt = t.extract_first(source)?;

        assert!(tt.is_some());

        let tt = tt.unwrap();

        println!("{:?} : {}", tt.data().name, tt.data().proto);

        Ok(())
    }
}
