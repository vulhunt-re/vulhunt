use std::str::FromStr;

use nom::branch::alt;
use nom::bytes::complete::{escaped_transform, is_not, tag, take_while1};
use nom::character::complete::{char, none_of};
use nom::combinator::{all_consuming, cut, eof, map, not, peek, rest, value, verify};
use nom::error::ParseError;
use nom::multi::fold_many0;
use nom::sequence::{delimited, preceded, separated_pair, terminated};
use nom::{IResult, Parser};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyValue {
    key: String,
    value: String,
}

impl KeyValue {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }

    pub fn parse(input: impl AsRef<str>) -> Result<Self, KeyValParseError> {
        let input = input.as_ref();
        match parse_full(input) {
            Ok((_, (key, value))) => Ok(KeyValue {
                key: key.to_owned(),
                value,
            }),
            Err(nom::Err::Error(e) | nom::Err::Failure(e)) => Err(e.into()),
            Err(nom::Err::Incomplete(_)) => Err(KeyValParseError::InvalidKey),
        }
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn into_parts(self) -> (String, String) {
        (self.key, self.value)
    }
}

impl FromStr for KeyValue {
    type Err = KeyValParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Hash)]
#[non_exhaustive]
pub enum KeyValParseError {
    #[error("invalid escape sequence: \\{0}")]
    InvalidEscapeSequence(char),
    #[error("invalid key: must start with letter or underscore, contain only alphanumerics and underscores")]
    InvalidKey,
    #[error("missing `=` separator")]
    MissingEquals,
    #[error("trailing characters after quoted value")]
    TrailingCharacters,
    #[error("unterminated double-quoted string")]
    UnterminatedDoubleQuote,
    #[error("unterminated single-quoted string")]
    UnterminatedSingleQuote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseContext {
    Key,
    Equals,
    DoubleQuoteClose,
    SingleQuoteClose,
    Trailing,
}

#[derive(Debug, Clone, PartialEq)]
struct Error<'a> {
    context: Option<ParseContext>,
    _input: &'a str,
}

impl From<Error<'_>> for KeyValParseError {
    fn from(e: Error<'_>) -> Self {
        match e.context {
            Some(ParseContext::Key) | None => KeyValParseError::InvalidKey,
            Some(ParseContext::Equals) => KeyValParseError::MissingEquals,
            Some(ParseContext::DoubleQuoteClose) => KeyValParseError::UnterminatedDoubleQuote,
            Some(ParseContext::SingleQuoteClose) => KeyValParseError::UnterminatedSingleQuote,
            Some(ParseContext::Trailing) => KeyValParseError::TrailingCharacters,
        }
    }
}

impl<'a> ParseError<&'a str> for Error<'a> {
    fn from_error_kind(input: &'a str, _kind: nom::error::ErrorKind) -> Self {
        Self {
            context: None,
            _input: input,
        }
    }

    fn append(_input: &'a str, _kind: nom::error::ErrorKind, other: Self) -> Self {
        other
    }
}

fn with_context<'a, O, F>(
    ctx: ParseContext,
    mut parser: F,
) -> impl FnMut(&'a str) -> IResult<&'a str, O, Error<'a>>
where
    F: Parser<&'a str, O, Error<'a>>,
{
    move |input| {
        parser.parse(input).map_err(|e| {
            e.map(|mut err| {
                err.context = Some(ctx);
                err
            })
        })
    }
}

fn is_key_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn parse_key<'a>(input: &'a str) -> IResult<&'a str, &'a str, Error<'a>> {
    with_context(
        ParseContext::Key,
        verify(take_while1(is_key_char), |s: &str| {
            s.chars().next().is_some_and(is_key_start)
        }),
    )(input)
}

fn parse_equals<'a>(input: &'a str) -> IResult<&'a str, char, Error<'a>> {
    with_context(ParseContext::Equals, char('='))(input)
}

fn parse_double_quoted_value<'a>(input: &'a str) -> IResult<&'a str, String, Error<'a>> {
    delimited(
        char('"'),
        escaped_transform(
            none_of("\"\\"),
            '\\',
            alt((
                value('"', char('"')),
                value('\\', char('\\')),
                value('\n', char('n')),
                value('\t', char('t')),
                value('\r', char('r')),
                value('$', char('$')),
                value('\0', char('0')),
            )),
        ),
        with_context(ParseContext::DoubleQuoteClose, cut(char('"'))),
    )(input)
}

fn parse_single_quoted_value<'a>(input: &'a str) -> IResult<&'a str, String, Error<'a>> {
    delimited(
        char('\''),
        fold_many0(
            alt((is_not("'"), map(tag("''"), |_| "'"))),
            String::new,
            |mut acc, s| {
                acc.push_str(s);
                acc
            },
        ),
        with_context(ParseContext::SingleQuoteClose, cut(char('\''))),
    )(input)
}

fn parse_unquoted_value<'a>(input: &'a str) -> IResult<&'a str, String, Error<'a>> {
    preceded(
        not(peek(alt((char('"'), char('\''))))),
        map(rest, str::to_owned),
    )(input)
}

fn parse_quoted_value<'a>(input: &'a str) -> IResult<&'a str, String, Error<'a>> {
    terminated(
        alt((parse_double_quoted_value, parse_single_quoted_value)),
        with_context(ParseContext::Trailing, cut(eof)),
    )(input)
}

fn parse_value<'a>(input: &'a str) -> IResult<&'a str, String, Error<'a>> {
    alt((parse_quoted_value, parse_unquoted_value))(input)
}

fn parse_kv_pair<'a>(input: &'a str) -> IResult<&'a str, (&'a str, String), Error<'a>> {
    separated_pair(parse_key, parse_equals, parse_value)(input)
}

fn parse_full<'a>(input: &'a str) -> IResult<&'a str, (&'a str, String), Error<'a>> {
    all_consuming(parse_kv_pair)(input)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_simple_unquoted() {
        let kv = KeyValue::parse("KEY=value").unwrap();
        assert_eq!(kv.key(), "KEY");
        assert_eq!(kv.value(), "value");
    }

    #[test]
    fn test_unquoted_with_spaces() {
        let kv = KeyValue::parse("KEY=hello world").unwrap();
        assert_eq!(kv.key(), "KEY");
        assert_eq!(kv.value(), "hello world");
    }

    #[test]
    fn test_empty_value() {
        let kv = KeyValue::parse("KEY=").unwrap();
        assert_eq!(kv.key(), "KEY");
        assert_eq!(kv.value(), "");
    }

    #[test]
    fn test_double_quoted_simple() {
        let kv = KeyValue::parse(r#"KEY="hello""#).unwrap();
        assert_eq!(kv.key(), "KEY");
        assert_eq!(kv.value(), "hello");
    }

    #[test]
    fn test_double_quoted_with_escapes() {
        let kv = KeyValue::parse(r#"MSG="line1\nline2""#).unwrap();
        assert_eq!(kv.key(), "MSG");
        assert_eq!(kv.value(), "line1\nline2");
    }

    #[test]
    fn test_double_quoted_escape_quote() {
        let kv = KeyValue::parse(r#"MSG="say \"hello\"""#).unwrap();
        assert_eq!(kv.key(), "MSG");
        assert_eq!(kv.value(), r#"say "hello""#);
    }

    #[test]
    fn test_double_quoted_escape_backslash() {
        let kv = KeyValue::parse(r#"PATH="C:\\Windows""#).unwrap();
        assert_eq!(kv.key(), "PATH");
        assert_eq!(kv.value(), r"C:\Windows");
    }

    #[test]
    fn test_double_quoted_escape_dollar() {
        let kv = KeyValue::parse(r#"MSG="cost is \$5""#).unwrap();
        assert_eq!(kv.key(), "MSG");
        assert_eq!(kv.value(), "cost is $5");
    }

    #[test]
    fn test_double_quoted_escape_tab_carriage() {
        let kv = KeyValue::parse(r#"MSG="tab\there\r""#).unwrap();
        assert_eq!(kv.key(), "MSG");
        assert_eq!(kv.value(), "tab\there\r");
    }

    #[test]
    fn test_double_quoted_escape_null() {
        let kv = KeyValue::parse(r#"MSG="null\0char""#).unwrap();
        assert_eq!(kv.key(), "MSG");
        assert_eq!(kv.value(), "null\0char");
    }

    #[test]
    fn test_single_quoted_simple() {
        let kv = KeyValue::parse("VAR='literal'").unwrap();
        assert_eq!(kv.key(), "VAR");
        assert_eq!(kv.value(), "literal");
    }

    #[test]
    fn test_single_quoted_preserves_dollar() {
        let kv = KeyValue::parse("VAR='$literal'").unwrap();
        assert_eq!(kv.key(), "VAR");
        assert_eq!(kv.value(), "$literal");
    }

    #[test]
    fn test_single_quoted_preserves_backslash() {
        let kv = KeyValue::parse(r"VAR='no\escapes'").unwrap();
        assert_eq!(kv.key(), "VAR");
        assert_eq!(kv.value(), r"no\escapes");
    }

    #[test]
    fn test_single_quoted_escaped_quote() {
        let kv = KeyValue::parse("VAR='it''s working'").unwrap();
        assert_eq!(kv.key(), "VAR");
        assert_eq!(kv.value(), "it's working");
    }

    #[test]
    fn test_equivalence() {
        let unquoted = KeyValue::parse("X=foo").unwrap();
        let single = KeyValue::parse("X='foo'").unwrap();
        let double = KeyValue::parse(r#"X="foo""#).unwrap();

        assert_eq!(unquoted.value(), single.value());
        assert_eq!(single.value(), double.value());
    }

    #[test]
    fn test_key_with_underscore() {
        let kv = KeyValue::parse("MY_VAR=value").unwrap();
        assert_eq!(kv.key(), "MY_VAR");
    }

    #[test]
    fn test_key_with_numbers() {
        let kv = KeyValue::parse("VAR123=value").unwrap();
        assert_eq!(kv.key(), "VAR123");
    }

    #[test]
    fn test_key_starting_with_underscore() {
        let kv = KeyValue::parse("_PRIVATE=value").unwrap();
        assert_eq!(kv.key(), "_PRIVATE");
    }

    #[test]
    fn test_error_invalid_key_starts_with_number() {
        let err = KeyValue::parse("123KEY=value").unwrap_err();
        assert_eq!(err, KeyValParseError::InvalidKey);
    }

    #[test]
    fn test_error_missing_equals() {
        let err = KeyValue::parse("KEY").unwrap_err();
        assert_eq!(err, KeyValParseError::MissingEquals);
    }

    #[test]
    fn test_error_unterminated_double_quote() {
        let err = KeyValue::parse(r#"KEY="unterminated"#).unwrap_err();
        assert_eq!(err, KeyValParseError::UnterminatedDoubleQuote);
    }

    #[test]
    fn test_error_unterminated_single_quote() {
        let err = KeyValue::parse("KEY='unterminated").unwrap_err();
        assert_eq!(err, KeyValParseError::UnterminatedSingleQuote);
    }

    #[test]
    fn test_error_trailing_characters() {
        let err = KeyValue::parse(r#"KEY="value" extra"#).unwrap_err();
        assert_eq!(err, KeyValParseError::TrailingCharacters);
    }

    #[test]
    fn test_from_str_trait() {
        let kv = "KEY=value".parse::<KeyValue>().unwrap();
        assert_eq!(kv.key(), "KEY");
        assert_eq!(kv.value(), "value");
    }
}
