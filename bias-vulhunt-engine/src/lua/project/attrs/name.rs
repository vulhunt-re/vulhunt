use crate::lua::scope::CheckScopeValue;
use crate::CheckerError;

fn matches_if<F>(value: &CheckScopeValue, f: F) -> Option<bool>
where
    F: Fn(&str) -> bool,
{
    if let Some(s) = value.as_str() {
        return Some(f(s));
    }

    let slice = value.as_slice()?;

    if slice.is_empty() {
        return None;
    }

    for item in slice {
        let s = item.as_str()?;

        if f(s) {
            return Some(true);
        }
    }

    Some(false)
}

pub(crate) fn matches_name<F>(name: &CheckScopeValue, f: F) -> Result<bool, CheckerError>
where
    F: Fn(&str) -> bool,
{
    matches_if(name, f)
        .ok_or_else(|| CheckerError::malformed_condition_with("invalid `name` format"))
}

pub(crate) fn matches_name_with_prefix<F>(
    prefix: &CheckScopeValue,
    f: F,
) -> Result<bool, CheckerError>
where
    F: Fn(&str) -> bool,
{
    matches_if(prefix, f)
        .ok_or_else(|| CheckerError::malformed_condition_with("invalid `name_with_prefix` format"))
}
