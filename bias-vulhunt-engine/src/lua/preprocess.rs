use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};

use bias_core::kb::Lazy;

use full_moon::ast::{Call, Expression, Field, FunctionArgs, FunctionCall, Prefix, Suffix};
use full_moon::tokenizer::{StringLiteralQuoteType, Token, TokenReference, TokenType};
use full_moon::visitors::VisitorMut;
use full_moon::{parse, ShortString};

use super::CheckerError;

#[derive(Default)]
pub struct ScopeRewrite {
    rewrites: BTreeMap<String, String>,
}

impl ScopeRewrite {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &impl Borrow<str>) -> Option<&str> {
        self.rewrites.get(key.borrow()).map(String::as_str)
    }

    pub fn parse_and_preprocess(
        &mut self,
        script: impl AsRef<str>,
    ) -> Result<String, CheckerError> {
        let ast = parse(script.as_ref()).map_err(CheckerError::Preprocess)?;
        let ast = self.visit_ast(ast);

        Ok(ast.to_string())
    }
}

type ScopeRewriteFunctions = BTreeMap<&'static str, BTreeSet<&'static str>>;

static SCOPE_REWRITE: Lazy<ScopeRewriteFunctions> = Lazy::new(|| {
    let mut functions = ScopeRewriteFunctions::new();

    functions.insert("project", ["with"].into_iter().collect());
    functions.insert("functions", ["with"].into_iter().collect());
    functions.insert("calls", ["with", "where"].into_iter().collect());

    functions
});

impl VisitorMut for ScopeRewrite {
    fn visit_function_call(&mut self, node: FunctionCall) -> FunctionCall {
        let Prefix::Name(n) = node.prefix() else {
            return node;
        };
        let TokenType::Identifier { identifier } = n.token().token_type() else {
            return node;
        };

        if identifier.as_str() != "scope" {
            return node;
        }

        let mut suffixes = node.suffixes().cloned().collect::<Vec<_>>();

        let Some(Suffix::Call(Call::MethodCall(ref mut method))) = suffixes.first_mut() else {
            return node;
        };

        let TokenType::Identifier { identifier } = method.name().token_type() else {
            return node;
        };

        let Some(targets) = SCOPE_REWRITE.get(identifier.as_str()) else {
            return node;
        };

        let FunctionArgs::TableConstructor(table) = method.args() else {
            return node;
        };

        let mut fields = table.fields().clone();
        for pair in fields.pairs_mut() {
            let Field::NameKey { key, value, .. } = pair.value_mut() else {
                continue;
            };

            let TokenType::Identifier { identifier: target } = key.token_type() else {
                continue;
            };

            if !targets.contains(target.as_str()) {
                continue;
            }

            let stringified = value.to_string();
            let lines = stringified.lines().count().checked_sub(1).unwrap_or(0);

            *value = if target.as_str() == "with" {
                let ident = format!("with_{}", self.rewrites.len());
                let value = Expression::String(TokenReference::new(
                    vec![],
                    Token::new(TokenType::StringLiteral {
                        literal: ShortString::new(&ident),
                        multi_line_depth: 0,
                        quote_type: StringLiteralQuoteType::Brackets,
                    }),
                    vec![],
                ));
                self.rewrites.insert(ident, stringified);
                value
            } else {
                Expression::String(TokenReference::new(
                    vec![],
                    Token::new(TokenType::StringLiteral {
                        literal: ShortString::new(stringified),
                        multi_line_depth: lines,
                        quote_type: StringLiteralQuoteType::Brackets,
                    }),
                    vec![],
                ))
            };
        }

        *method = method.clone().with_args(FunctionArgs::TableConstructor(
            table.clone().with_fields(fields),
        ));

        node.with_suffixes(suffixes)
    }
}

#[allow(unused)]
struct AnchorCallsWhereRewrite;

impl VisitorMut for AnchorCallsWhereRewrite {
    fn visit_function_call(&mut self, node: FunctionCall) -> FunctionCall {
        let Prefix::Name(n) = node.prefix() else {
            return node;
        };
        let TokenType::Identifier { identifier } = n.token().token_type() else {
            return node;
        };

        if &**identifier != "anchor" {
            return node;
        }

        let mut suffixes = node.suffixes().cloned().collect::<Vec<_>>();

        let Some(Suffix::Call(Call::MethodCall(ref mut method))) = suffixes.first_mut() else {
            return node;
        };
        let TokenType::Identifier { identifier } = method.name().token_type() else {
            return node;
        };

        if &**identifier != "calls" {
            return node;
        }

        let FunctionArgs::TableConstructor(table) = method.args() else {
            return node;
        };

        let mut fields = table.fields().clone();
        for pair in fields.pairs_mut() {
            let Field::NameKey { key, value, .. } = pair.value_mut() else {
                continue;
            };

            if !matches!(key.token_type(), TokenType::Identifier { identifier } if &**identifier == "where")
            {
                continue;
            }

            let stringified = value.to_string();
            let lines = stringified.lines().count().checked_sub(1).unwrap_or(0);

            *value = Expression::String(TokenReference::new(
                vec![],
                Token::new(TokenType::StringLiteral {
                    literal: ShortString::new(stringified),
                    multi_line_depth: lines,
                    quote_type: StringLiteralQuoteType::Brackets,
                }),
                vec![],
            ));
        }

        *method = method.clone().with_args(FunctionArgs::TableConstructor(
            table.clone().with_fields(fields),
        ));

        node.with_suffixes(suffixes)
    }
}

pub fn parse_and_preprocess(script: impl AsRef<str>) -> Result<String, CheckerError> {
    let mut rewrites = ScopeRewrite::default();
    let mut output = rewrites.parse_and_preprocess(script)?;

    if rewrites.rewrites.is_empty() {
        return Ok(output);
    }

    output.push_str("\n__scope_handlers = { }\n");

    for (k, v) in rewrites.rewrites {
        output.push_str("__scope_handlers.");
        output.push_str(k.as_str());
        output.push_str(" = ");
        output.push_str(v.as_str());
        output.push_str("\n");
    }

    Ok(output)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[ignore]
    fn test_parse() -> Result<(), Box<dyn std::error::Error>> {
        let script1 = r#"scope.functions {
            where = function (project, context) end,
        }"#;
        let script2 = r#"scope.functions { where = hello }"#;

        let ast1 = parse(script1.as_ref()).map_err(CheckerError::Preprocess)?;
        let ast2 = parse(script2.as_ref()).map_err(CheckerError::Preprocess)?;

        println!("{ast1:#?}");
        println!("{ast2:#?}");

        Ok(())
    }
}
