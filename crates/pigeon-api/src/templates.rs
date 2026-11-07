//! Template rendering (`{{variable}}` substitution).
//!
//! The contract's template surface is deliberately minimal: `subject`, `html`
//! and `text` may contain `{{name}}` placeholders that are replaced with the
//! `variables` object of the send request. No expressions, no loops, no
//! escaping — a template is text with holes, so rendering can never execute
//! anything and a missing variable cannot break the send.

use serde_json::{Map, Value};

/// Replace every `{{name}}` (or `{{ name }}`) placeholder whose `name` exists in
/// `variables`. Unknown placeholders are left verbatim: silently deleting them
/// would hide a typo in the caller's template, and rendering them as empty would
/// lose the only evidence of what was intended.
pub fn render(template: &str, variables: &Map<String, Value>) -> String {
    if variables.is_empty() || !template.contains("{{") {
        return template.to_string();
    }
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let Some(end) = rest[start + 2..].find("}}") else {
            break;
        };
        out.push_str(&rest[..start]);
        let name = rest[start + 2..start + 2 + end].trim();
        match variables.get(name) {
            Some(value) => out.push_str(&stringify(value)),
            None => out.push_str(&rest[start..start + 2 + end + 2]),
        }
        rest = &rest[start + 2 + end + 2..];
    }
    out.push_str(rest);
    out
}

/// Render a template value to text: strings verbatim, everything else as JSON.
fn stringify(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, Value)]) -> Map<String, Value> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.clone()))
            .collect()
    }

    #[test]
    fn substitutes_known_variables_including_spaced_syntax() {
        let variables = vars(&[
            ("name", Value::String("Dana".into())),
            ("count", Value::from(3)),
        ]);
        assert_eq!(
            render("Hi {{name}}, you have {{ count }} items", &variables),
            "Hi Dana, you have 3 items"
        );
    }

    #[test]
    fn unknown_placeholders_are_left_verbatim() {
        let variables = vars(&[("name", Value::String("Dana".into()))]);
        assert_eq!(
            render("Hi {{name}} / {{missing}}", &variables),
            "Hi Dana / {{missing}}"
        );
    }

    #[test]
    fn text_without_placeholders_is_unchanged() {
        let variables = vars(&[("name", Value::String("Dana".into()))]);
        assert_eq!(render("plain text", &variables), "plain text");
        assert_eq!(render("plain text", &Map::new()), "plain text");
    }

    #[test]
    fn unterminated_placeholders_do_not_lose_text() {
        let variables = vars(&[("name", Value::String("Dana".into()))]);
        assert_eq!(render("Hi {{name} oops", &variables), "Hi {{name} oops");
        assert_eq!(render("{{", &variables), "{{");
    }

    #[test]
    fn empty_and_null_values_render_predictably() {
        let variables = vars(&[
            ("empty", Value::String(String::new())),
            ("nil", Value::Null),
        ]);
        assert_eq!(render("[{{empty}}][{{nil}}]", &variables), "[][]");
    }

    #[test]
    fn structural_values_render_as_json() {
        let variables = vars(&[("obj", serde_json::json!({"a": 1}))]);
        assert_eq!(render("{{obj}}", &variables), "{\"a\":1}");
    }

    #[test]
    fn injection_attempts_stay_text() {
        // A variable value containing markup is inserted literally; the
        // template engine never re-parses its own output.
        let variables = vars(&[("name", Value::String("{{secret}}".into()))]);
        assert_eq!(render("Hi {{name}}", &variables), "Hi {{secret}}");
    }
}
