use super::*;
use serde_json::{json, Value};

const ENYO_ARGS: &str = include_str!("enyo-ask-args.json");
const ENYO_SESSION: &str = include_str!("enyo-session.jsonl");

fn enyo() -> ParsedForm {
    let args: Value = serde_json::from_str(ENYO_ARGS).unwrap();
    parse(form_html(Some(&args)).unwrap())
}

fn text(value: &str) -> Option<FormValue> {
    Some(FormValue::Text(value.into()))
}

fn choice(field: &Field) -> &Choice {
    field.choice().expect("a choice field")
}

#[test]
fn enyo_form_parses_into_five_radio_fields_with_recommendations() {
    let form = enyo();
    let wire = form.to_wire();
    assert_eq!(
        wire.intro.as_deref(),
        Some("Before enyo-ui starts building from iteration 5, five choices. My recommendation is preselected.")
    );
    let names: Vec<&str> = wire
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect();
    assert_eq!(names, ["where", "who", "scope", "picks", "form"]);
    let where_ = &wire.fields[0];
    assert_eq!(where_.kind, AskFormFieldKind::Choice);
    assert_eq!(where_.title.as_deref(), Some("Where to build"));
    assert!(where_
        .description
        .as_deref()
        .unwrap()
        .starts_with("lenscale.ai is public today (the 1 Nov landing)."));
    assert!(!where_.multi && !where_.select && where_.other && !where_.required);
    assert_eq!(where_.options.len(), 2);
    assert_eq!(where_.options[0].value, "preview");
    assert!(where_.options[0].checked && !where_.options[1].checked);
    assert!(where_.options[1]
        .label
        .starts_with("Hide lenscale.ai now: visitors"));
    assert_eq!(wire.fields[2].description, None);
    assert!(form.drivable());

    let compat = form.compat_questions(&wire);
    assert_eq!(compat.len(), 5);
    assert_eq!(compat[0].question, "Where to build");
    assert_eq!(compat[0].recommended, Some(0));
    assert_eq!(compat[4].options.len(), 2);
}

/// The answers omp recorded for the real enyo session: the port of
/// `fieldQuestions`/`formAnswers` reproduces them byte for byte.
#[test]
fn enyo_answers_match_what_omp_recorded() {
    let result: Value = serde_json::from_str(ENYO_SESSION.lines().nth(1).unwrap()).unwrap();
    let recorded: Vec<AskFormAnswer> =
        serde_json::from_value(result["message"]["details"]["answers"].clone()).unwrap();
    let form = enyo();
    let mut data: Vec<Option<FormValue>> = form
        .fields
        .iter()
        .map(|field| form.default_value(field))
        .collect();
    data[4] = text("email");
    assert_eq!(form.answers(&data), recorded);
}

#[test]
fn only_the_first_form_counts_and_hidden_inputs_are_not_fields() {
    let form = parse(
        r#"<p>outside</p><form><input type="hidden" name="token" value="t1">
        <label><input type="checkbox" name="ok" checked> Ship</label></form>
        <form><input name="later"></form>"#,
    );
    assert_eq!(form.hidden, [("token".to_string(), "t1".to_string())]);
    assert_eq!(form.fields.len(), 1);
    let wire = form.to_wire();
    assert_eq!(wire.intro, None);
    assert_eq!(wire.fields[0].name, "ok");
    // A lone checkbox never gets Other.
    assert!(!wire.fields[0].other);
}

#[test]
fn checkbox_groups_join_by_type_and_name_across_the_document() {
    let form = parse(
        r#"<form><table><tr><th>Tool</th></tr>
        <tr><td><input type="checkbox" name="tools" value="ci" checked></td><td>CI</td></tr>
        <tr><td><label><input type="checkbox" name="tools" value="tf" required> Terraform</label></td></tr>
        </table><input type="radio" name="tools" value="x"></form>"#,
    );
    assert_eq!(form.fields.len(), 2, "radio `tools` is a different group");
    let tools = choice(&form.fields[0]);
    assert!(tools.multi && tools.other && form.fields[0].required);
    let labels: Vec<&str> = tools
        .options
        .iter()
        .map(|option| option.label.as_str())
        .collect();
    // The unlabeled control borrows its cell's text, else the column header.
    assert_eq!(labels, ["Tool", "Terraform"]);
    assert_eq!(
        form.default_value(&form.fields[0]),
        Some(FormValue::List(vec!["ci".into()]))
    );
}

#[test]
fn select_has_no_other_and_defaults_to_the_first_enabled_option() {
    let form = parse(
        r#"<form><label>Region <select name="region">
        <option disabled>pick</option><option value="us">US East</option><option>EU</option>
        </select></label>
        <select name="langs" multiple><option selected>Rust</option><option selected>Go</option></select></form>"#,
    );
    let region = &form.fields[0];
    assert_eq!(region.label, "Region");
    let select = choice(region);
    assert!(select.select && !select.multi && !select.other && select.is_dropdown());
    assert_eq!(select.initial_checked(), [1]);
    assert_eq!(
        select.options[2].value, "EU",
        "value falls back to the text"
    );
    let langs = choice(&form.fields[1]);
    assert!(langs.multi && !langs.other && !langs.is_dropdown());
    assert_eq!(langs.initial_checked(), [0, 1]);
}

#[test]
fn text_fields_keep_their_constraints() {
    let form = parse(
        r#"<form><fieldset><legend>Contact</legend>
        <label>Email <input type="EMAIL" name="email" required placeholder="you@x" maxlength="40"></label>
        <label for="n">Count</label><input id="n" type="number" name="count" min="1" max="9" value="3">
        <textarea name="sentry_dsn" minlength="5">
prefilled</textarea>
        <input name="code" pattern="[A-Z]{3}" aria-label="Code">
        </fieldset></form>"#,
    );
    let wire = form.to_wire();
    let email = &wire.fields[0];
    assert_eq!(email.kind, AskFormFieldKind::Text);
    assert_eq!(email.input_type.as_deref(), Some("email"));
    assert_eq!(
        email.title.as_deref(),
        Some("Email"),
        "own label in a shared fieldset"
    );
    assert_eq!(email.placeholder.as_deref(), Some("you@x"));
    assert_eq!(email.maxlength, Some(40));
    assert!(email.required);
    let count = &wire.fields[1];
    assert_eq!(count.title.as_deref(), Some("Count"));
    assert_eq!(count.value.as_deref(), Some("3"));
    assert_eq!(count.min, Some(1.into()));
    assert_eq!(count.max, Some(9.into()));
    let notes = &wire.fields[2];
    assert_eq!(notes.input_type.as_deref(), Some("textarea"));
    assert_eq!(notes.title.as_deref(), Some("sentry dsn"));
    assert_eq!(notes.value.as_deref(), Some("prefilled"));
    assert_eq!(notes.minlength, Some(5));
    assert_eq!(wire.fields[3].pattern.as_deref(), Some("[A-Z]{3}"));
    assert_eq!(wire.fields[3].title.as_deref(), Some("Code"));

    let error =
        |index: usize, value: Option<FormValue>| field_error(&form.fields[index], value.as_ref());
    let field = |index: usize| &form.fields[index];
    assert_eq!(error(0, None), Some("Required".into()));
    assert_eq!(
        error(0, text("nope")),
        Some("Enter an email address".into())
    );
    assert_eq!(error(0, text("a@b")), None);
    assert_eq!(
        error(1, Some(FormValue::Number(12.0))),
        Some("Must be at most 9".into())
    );
    assert_eq!(error(1, text("x")), Some("Enter a number".into()));
    assert_eq!(
        error(2, text("abc")),
        Some("Needs at least 5 characters".into())
    );
    assert_eq!(error(3, text("abcd")), Some("Must match [A-Z]{3}".into()));
    assert_eq!(error(3, text("ABC")), None);
    assert_eq!(
        form.default_value(field(1)),
        Some(FormValue::Number(3.0)),
        "number inputs submit numbers"
    );
}

#[test]
fn other_is_added_to_groups_of_two_or_more_unless_one_offers_its_own() {
    let form = parse(
        r#"<form>
        <label><input type="radio" name="a" value="1"> One</label>
        <label><input type="radio" name="a" value="2"> Two</label>
        <label><input type="radio" name="b" value="1"> One</label>
        <label><input type="radio" name="b" value="o"> Other (say which)</label>
        <label><input type="radio" name="c" value="1"> Only</label>
        <label><input type="checkbox" name="d" value="1"> One</label>
        <label><input type="checkbox" name="d" value="2"> Otherwise</label>
        </form>"#,
    );
    let other: Vec<bool> = form
        .fields
        .iter()
        .map(|field| choice(field).other)
        .collect();
    // "Otherwise" is not "Other": the word must end there.
    assert_eq!(other, [true, false, false, true]);
}

#[test]
fn the_last_checked_radio_wins() {
    let form = parse(
        r#"<form><input type="radio" name="r" value="a" checked>
        <input type="radio" name="r" value="b" checked><input type="radio" name="r" value="c"></form>"#,
    );
    let wire = form.to_wire();
    let checked: Vec<bool> = wire.fields[0]
        .options
        .iter()
        .map(|option| option.checked)
        .collect();
    assert_eq!(checked, [false, true, false]);
    assert_eq!(form.default_value(&form.fields[0]), text("b"));
    assert_eq!(form.compat_questions(&wire)[0].recommended, Some(1));
}

#[test]
fn other_answers_read_as_other_and_multi_answers_join() {
    let form = parse(
        r#"<form><p>Pick tools</p>
        <label><input type="checkbox" name="t" value="ci"> CI</label>
        <label><input type="checkbox" name="t" value="tf"> Terraform</label>
        <p>Which DB?</p>
        <label><input type="radio" name="db" value="pg"> Postgres</label>
        <label><input type="radio" name="db" value="my"> MySQL</label></form>"#,
    );
    let data = [
        Some(FormValue::List(vec!["ci".into(), "nix".into()])),
        text("Mongo"),
    ];
    let answers = form.answers(&data);
    assert_eq!(answers[0].question, "Pick tools");
    assert_eq!(answers[0].answer, "CI, Other: nix");
    assert_eq!(answers[1].question, "Which DB?");
    assert_eq!(answers[1].answer, "Other: Mongo");
    let wire = form.to_wire();
    assert_eq!(wire.intro.as_deref(), Some("Pick tools"));
    assert_eq!(wire.fields[0].description, None);
    assert_eq!(wire.fields[1].description.as_deref(), Some("Which DB?"));
}

#[test]
fn duplicate_or_missing_names_are_not_drivable() {
    assert!(!parse(r#"<form><input name="a"><textarea name="a"></textarea></form>"#).drivable());
    assert!(!parse(r#"<form><input><p>x</p></form>"#).drivable());
    assert!(parse(r#"<form><input><input name="b"></form>"#).drivable());
}

#[test]
fn context_blocks_flatten_to_plain_text() {
    let form = parse(
        "<form><h2>Plan</h2><ul><li>one<li>two</ul><pre>\n  code\n</pre>\
         <table><tr><th>A</th><th>B</th></tr><tr><td>1</td><td>2</td></tr></table>\
         <img src=\"x.png\" alt=\"chart\"><img alt=\"no src\">\
         <p>a <b>bold</b>\n   move<br> next</p><input name=\"z\"></form>",
    );
    // omp's `normalizeSpans` keeps a newline in source text as a line break
    // (`/[^\S\n]+/` collapses everything else), so "bold\n   move" breaks.
    assert_eq!(
        form.to_wire().intro.as_deref(),
        Some("Plan\n\n• one\n• two\n\n  code\n\nA · B\n1 · 2\n\nchart\n\na bold\nmove\nnext")
    );
}

#[test]
fn ask_arguments_without_html_are_not_forms() {
    assert_eq!(form_html(Some(&json!({"questions": []}))), None);
    assert_eq!(form_html(None), None);
}

/// #392 F6: omp's parser decodes only its own entity table; others stay as
/// written, and so does the label omp draws.
#[test]
fn entities_decode_as_omps_parser_does() {
    let form = parse(
        r#"<form><label><input type="radio" name="a" value="1"> Go &rarr; &amp; &eacute; &#x41;&#66; &bogus;</label>
        <label><input type="radio" name="a" value="2" title="x&quot;y"> B</label></form>"#,
    );
    let labels: Vec<&str> = choice(&form.fields[0])
        .options
        .iter()
        .map(|option| option.label.as_str())
        .collect();
    assert_eq!(labels, ["Go &rarr; & é AB &bogus;", "B"]);
}

/// #392 F7: `pattern` is an ECMAScript `v`-flag regex, whose `\W` is ASCII.
#[test]
fn patterns_follow_ecmascript_semantics() {
    let form =
        parse(r#"<form><input name="w" pattern="\W+"><input name="bad" pattern="(?<x"></form>"#);
    assert_eq!(field_error(&form.fields[0], text("é").as_ref()), None);
    assert_eq!(
        field_error(&form.fields[0], text("a").as_ref()),
        Some("Must match \\W+".into())
    );
    // A pattern JS cannot compile is ignored, as omp does.
    assert_eq!(
        field_error(&form.fields[1], text("anything").as_ref()),
        None
    );
}

/// #392 F8: a field that submits nothing reads the hidden input of its name.
#[test]
fn predicted_answers_fall_back_to_hidden_inputs() {
    let form = parse(
        r#"<form><input type="hidden" name="enabled" value="no">
        <label><input type="checkbox" name="enabled" value="yes"> Enable</label></form>"#,
    );
    let data = vec![form.default_value(&form.fields[0])];
    assert_eq!(form.answers(&data)[0].answer, "no");
}

/// #392 F9: numbers read as JS `String(number)` writes them.
#[test]
fn numbers_format_like_javascript() {
    for (value, expected) in [
        (0.0000001, "1e-7"),
        (0.000001, "0.000001"),
        (1e21, "1e+21"),
        (123456789012345680000.0, "123456789012345680000"),
        (1.5, "1.5"),
        (-0.25, "-0.25"),
        (3.0, "3"),
        (2.5e-8, "2.5e-8"),
    ] {
        assert_eq!(js_number_string(value), expected, "{value}");
    }
    let form = parse(r#"<form><input type="number" name="n" value="0.0000001"></form>"#);
    let data = vec![form.default_value(&form.fields[0])];
    assert_eq!(form.answers(&data)[0].answer, "1e-7");
}

/// #392 F10: fields that share a name keep their own titles.
#[test]
fn compat_questions_keep_each_fields_own_title() {
    let form = parse(
        r#"<form><label>Primary <select name="db"><option>a</option></select></label>
        <label>Backup <select name="db"><option>b</option></select></label></form>"#,
    );
    let wire = form.to_wire();
    let titles: Vec<String> = form
        .compat_questions(&wire)
        .into_iter()
        .map(|question| question.question)
        .collect();
    assert_eq!(titles, ["Primary", "Backup"]);
}
