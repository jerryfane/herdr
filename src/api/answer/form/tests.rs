use std::collections::BTreeMap;

use super::*;
use crate::agent_transcript::ask_form::parse;

const FORM: &str = r#"<form><p>Intro</p>
<fieldset><legend>Database</legend>
<label><input type="radio" name="db" value="pg" checked> Postgres</label>
<label><input type="radio" name="db" value="my"> MySQL</label>
<label><input type="radio" name="db" value="x" disabled> Oracle</label>
<label><input type="radio" name="db" value="sq"> SQLite</label>
</fieldset>
<fieldset><legend>Tools</legend>
<label><input type="checkbox" name="tools" value="ci" checked> CI</label>
<label><input type="checkbox" name="tools" value="tf"> Terraform</label>
<label><input type="checkbox" name="tools" value="nx"> Nix</label>
</fieldset>
<label>Region <select name="region"><option value="us">US</option><option value="eu" disabled>EU</option><option value="ap">AP</option></select></label>
<label>Notes <input name="notes" value="draft"></label>
</form>"#;

fn values(pairs: &[(&str, AskFormValue)]) -> BTreeMap<String, AskFormValue> {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), value.clone()))
        .collect()
}

fn options(list: &[&str]) -> AskFormValue {
    AskFormValue {
        options: Some(list.iter().map(|value| (*value).to_owned()).collect()),
        ..AskFormValue::default()
    }
}

fn keys(list: &[&'static str]) -> Action {
    Action::Keys(list.to_vec())
}

#[test]
fn stops_follow_dialog_ts() {
    let form = parse(FORM);
    assert_eq!(
        stops(&form),
        [
            Stop::Option {
                field: 0,
                option: 0
            },
            Stop::Option {
                field: 0,
                option: 1
            },
            Stop::Option {
                field: 0,
                option: 3
            },
            Stop::Other { field: 0 },
            Stop::Option {
                field: 1,
                option: 0
            },
            Stop::Option {
                field: 1,
                option: 1
            },
            Stop::Option {
                field: 1,
                option: 2
            },
            Stop::Other { field: 1 },
            Stop::Select { field: 2 },
            Stop::Text { field: 3 },
            Stop::Submit,
        ]
    );
}

#[test]
fn accepting_the_recommendations_tabs_through_and_submits() {
    let form = parse(FORM);
    let plan = plan(&form, &BTreeMap::new()).unwrap();
    assert_eq!(
        plan.actions,
        [
            keys(&["up"]),
            keys(&["tab", "tab", "left", "tab", "ctrl+e", "ctrl+u"]),
            Action::Text("draft".into()),
            keys(&["tab", "enter"]),
        ]
    );
    let answers: Vec<&str> = plan
        .expected
        .iter()
        .map(|answer| answer.answer.as_str())
        .collect();
    assert_eq!(answers, ["Postgres", "CI", "US", "draft"]);
}

#[test]
fn radio_moves_down_over_enabled_options_and_enters() {
    let form = parse(FORM);
    let plan = plan(&form, &values(&[("db", options(&["sq"]))])).unwrap();
    assert_eq!(
        plan.actions,
        [
            keys(&["up"]),
            keys(&["down", "down", "enter", "tab", "left", "tab", "ctrl+e", "ctrl+u"]),
            Action::Text("draft".into()),
            keys(&["tab", "enter"]),
        ]
    );
    assert_eq!(plan.expected[0].answer, "SQLite");
}

#[test]
fn radio_other_types_on_the_other_row() {
    let form = parse(FORM);
    let value = AskFormValue {
        options: Some(Vec::new()),
        other: Some(" CockroachDB ".into()),
        text: None,
    };
    let plan = plan(&form, &values(&[("db", value)])).unwrap();
    assert_eq!(
        plan.actions,
        [
            keys(&["up"]),
            keys(&["down", "down", "down"]),
            Action::Text("CockroachDB".into()),
            keys(&["enter", "tab", "left", "tab", "ctrl+e", "ctrl+u"]),
            Action::Text("draft".into()),
            keys(&["tab", "enter"]),
        ]
    );
    assert_eq!(plan.expected[0].answer, "Other: CockroachDB");
}

#[test]
fn checkbox_toggles_only_the_differences_then_tabs() {
    let form = parse(FORM);
    let value = AskFormValue {
        options: Some(vec!["nx".into()]),
        other: Some("just".into()),
        text: None,
    };
    let plan = plan(&form, &values(&[("tools", value)])).unwrap();
    assert_eq!(
        plan.actions,
        [
            keys(&["up"]),
            keys(&["tab", "space", "down", "down", "space", "down"]),
            Action::Text("just".into()),
            keys(&["tab", "left", "tab", "ctrl+e", "ctrl+u"]),
            Action::Text("draft".into()),
            keys(&["tab", "enter"]),
        ]
    );
    assert_eq!(plan.expected[1].answer, "Nix, Other: just");
}

#[test]
fn select_steps_over_disabled_options_with_arrows() {
    let form = parse(FORM);
    let plan = plan(&form, &values(&[("region", options(&["ap"]))])).unwrap();
    assert_eq!(
        plan.actions,
        [
            keys(&["up"]),
            keys(&["tab", "tab", "left", "right", "tab", "ctrl+e", "ctrl+u"]),
            Action::Text("draft".into()),
            keys(&["tab", "enter"]),
        ]
    );
    assert_eq!(plan.expected[2].answer, "AP");
}

#[test]
fn text_clears_the_prefill_and_types() {
    let form = parse(FORM);
    let value = AskFormValue {
        text: Some("ship friday".into()),
        ..AskFormValue::default()
    };
    let plan = plan(&form, &values(&[("notes", value)])).unwrap();
    assert_eq!(
        plan.actions,
        [
            keys(&["up"]),
            keys(&["tab", "tab", "left", "tab", "ctrl+e", "ctrl+u"]),
            Action::Text("ship friday".into()),
            keys(&["tab", "enter"]),
        ]
    );
}

#[test]
fn invalid_values_name_the_field() {
    let form = parse(FORM);
    let message = |pairs: &[(&str, AskFormValue)]| plan(&form, &values(pairs)).unwrap_err().message;
    assert_eq!(message(&[("nope", options(&[]))]), "nope: unknown field");
    assert_eq!(
        message(&[("db", options(&["pg", "my"]))]),
        "db: choose only one option"
    );
    assert_eq!(
        message(&[("db", options(&["x"]))]),
        "db: option \"x\" is disabled"
    );
    assert_eq!(
        message(&[("db", options(&["zz"]))]),
        "db: unknown option \"zz\""
    );
    assert_eq!(
        message(&[(
            "region",
            AskFormValue {
                other: Some("y".into()),
                ..AskFormValue::default()
            }
        )]),
        "region: this field has no Other answer"
    );
    let required = parse(r#"<form><input name="who" required></form>"#);
    let error = plan(&required, &BTreeMap::new()).unwrap_err();
    assert_eq!(
        (error.code.as_str(), error.message.as_str()),
        ("ask_form_invalid", "who: Required")
    );
}

#[test]
fn the_screen_check_wants_the_untouched_form() {
    let form = parse(FORM);
    let start = "agent: Two quick choices\n\
        Database\n\
        ❯ ◉ Postgres\n    ○ MySQL\n    ○ Oracle\n    ○ SQLite\n    ○ Other: type your own\n\
        Tools\n    ☑ CI\n    ☐ Terraform\n    ☐ Nix\n    ☐ Other: type your own\n  Submit";
    assert!(at_start(start, &form));
    let moved = start.replace("❯ ◉ Postgres\n    ○ MySQL", "  ◉ Postgres\n❯ ○ MySQL");
    assert!(!at_start(&moved, &form));
    let changed = start.replace("☐ Terraform", "☑ Terraform");
    assert!(!at_start(&changed, &form));
    let typed = start.replacen("○ Other: type your own", "○ Other: Mongo", 1);
    assert!(!at_start(&typed, &form));
    assert!(!at_start("$ omp\n> ", &form), "no form on screen");
}

/// A present entry without `options` (`"tools": {}`) means none chosen:
/// only a missing name keeps the default.
#[test]
fn a_present_entry_without_options_unticks_a_checkbox_group() {
    let form = parse(FORM);
    let plan = plan(&form, &values(&[("tools", AskFormValue::default())])).unwrap();
    assert_eq!(
        plan.actions,
        [
            keys(&["up"]),
            keys(&["tab", "space", "tab", "left", "tab", "ctrl+e", "ctrl+u"]),
            Action::Text("draft".into()),
            keys(&["tab", "enter"]),
        ]
    );
    assert_eq!(plan.expected[1].answer, "");

    let required = parse(
        r#"<form><label><input type="checkbox" name="t" value="a" checked required> A</label>
        <label><input type="checkbox" name="t" value="b"> B</label></form>"#,
    );
    let error = super::plan(&required, &values(&[("t", AskFormValue::default())])).unwrap_err();
    assert_eq!(
        (error.code.as_str(), error.message.as_str()),
        ("ask_form_invalid", "t: Select at least one")
    );
    // Missing keeps the default, which satisfies `required`.
    assert!(super::plan(&required, &BTreeMap::new()).is_ok());
}

#[test]
fn a_present_radio_entry_without_options_needs_other() {
    let form = parse(FORM);
    let error = plan(&form, &values(&[("db", AskFormValue::default())])).unwrap_err();
    assert_eq!(error.message, "db: choose one option or Other");
    let other = AskFormValue {
        other: Some("Mongo".into()),
        ..AskFormValue::default()
    };
    assert!(plan(&form, &values(&[("db", other)])).is_ok());
}

fn screen(rows: &[&str]) -> String {
    rows.join("\n")
}

/// #392 F1/F2: a text field is cleared wherever its caret is and retyped,
/// even when kept, so neither the caret omp opens it with nor an edit made
/// in the terminal reaches the submission.
#[test]
fn text_fields_are_cleared_caret_independently_and_always_set() {
    let form = parse(
        r#"<form><input name="notes" value="draft"><textarea name="long">a
b</textarea></form>"#,
    );
    let plan = plan(&form, &BTreeMap::new()).unwrap();
    let Action::Keys(first) = &plan.actions[1] else {
        panic!("{:?}", plan.actions);
    };
    assert_eq!(first, &["ctrl+e", "ctrl+u"]);
    assert_eq!(plan.actions[2], Action::Text("draft".into()));
    let Action::Keys(second) = &plan.actions[3] else {
        panic!("{:?}", plan.actions);
    };
    assert_eq!(second[0], "tab");
    assert_eq!(&second[1..3], ["ctrl+e", "ctrl+u"]);
    assert_eq!(
        second.iter().filter(|key| **key == "ctrl+k").count(),
        2 * 199
    );
    assert_eq!(plan.actions[4], Action::Text("a\nb".into()));
}

/// #392 F2: a dropdown is set outright, from whatever it shows.
#[test]
fn dropdowns_are_set_outright() {
    let form = parse(FORM);
    let plan = plan(&form, &BTreeMap::new()).unwrap();
    let Action::Keys(keys) = &plan.actions[1] else {
        panic!("{:?}", plan.actions);
    };
    // Region has 2 enabled options: one ← reaches US from either.
    assert_eq!(&keys[..4], ["tab", "tab", "left", "tab"]);
}

/// #392 F3: labels sharing a long prefix are told apart; focus on the third
/// is not the first stop.
#[test]
fn the_screen_check_needs_the_whole_label() {
    let form = parse(
        r#"<form><label><input type="radio" name="r" value="a"> abcdefghijkl A</label>
        <label><input type="radio" name="r" value="b"> abcdefghijkl B</label>
        <label><input type="radio" name="r" value="c"> abcdefghijkl C</label></form>"#,
    );
    let rows = |focus: usize| {
        let mut lines = vec!["Ask".to_owned()];
        for (index, letter) in ["A", "B", "C"].iter().enumerate() {
            let cursor = if index == focus { "❯ " } else { "  " };
            lines.push(format!("│ {cursor}○ abcdefghijkl {letter}   │"));
        }
        lines.push("│   ○ Other: type your own │".into());
        lines.join("\n")
    };
    assert!(at_start(&rows(0), &form));
    assert!(!at_start(&rows(2), &form));
}

/// #392 F4: an option of the agent's own labelled "Other: …" is a label,
/// not the synthetic Other row.
#[test]
fn an_option_labelled_other_is_an_ordinary_row() {
    let form = parse(
        r#"<form><label><input type="radio" name="r" value="a" checked> A</label>
        <label><input type="radio" name="r" value="s"> Other: skip</label></form>"#,
    );
    assert!(!choice_other(&form));
    assert!(at_start(
        &screen(&["❯ ◉ A", "  ○ Other: skip", "  Submit"]),
        &form
    ));
}

fn choice_other(form: &ParsedForm) -> bool {
    form.fields[0].choice().unwrap().other
}

/// #392 F5: Other can be the first stop (every option disabled).
#[test]
fn other_can_be_the_first_stop() {
    let form = parse(
        r#"<form><label><input type="radio" name="r" value="a" disabled> A</label>
        <label><input type="radio" name="r" value="b" disabled> B</label></form>"#,
    );
    assert_eq!(stops(&form)[0], Stop::Other { field: 0 });
    // Focused and empty, omp draws a cursor block before the placeholder.
    let start = screen(&["  ○ A", "  ○ B", "❯ ○ Other:  type your own", "  Submit"]);
    assert!(at_start(&start, &form));
    let typed = screen(&["  ○ A", "  ○ B", "❯ ○ Other: x", "  Submit"]);
    assert!(!at_start(&typed, &form));
}
