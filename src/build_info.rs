//! Build identity helpers.

pub const BASE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn channel() -> &'static str {
    non_empty(option_env!("HERDR_BUILD_CHANNEL")).unwrap_or("stable")
}

pub fn build_id() -> Option<&'static str> {
    non_empty(option_env!("HERDR_BUILD_ID"))
}

pub fn version() -> String {
    match channel() {
        "stable" => BASE_VERSION.to_string(),
        channel => match build_id() {
            Some(build_id) => format!("{BASE_VERSION}-{channel}.{build_id}"),
            None => format!("{BASE_VERSION}-{channel}"),
        },
    }
}

pub fn is_preview() -> bool {
    channel() == "preview"
}

/// The short git commit this binary was built from, when known. Sourced from `HERDR_BUILD_COMMIT`
/// (stamped by `build.rs` from git, or set explicitly by CI / the fleet build scripts); `None` for a
/// build with no git context (e.g. a source tarball).
pub fn commit() -> Option<&'static str> {
    non_empty(option_env!("HERDR_BUILD_COMMIT"))
}

/// The version for HUMAN display, with the commit appended when known: `"0.8.0 (abc1234)"`, else just
/// the version. Kept separate from [`version`] on purpose — `version()` is compared by exact string
/// match in the live-handoff, so the commit must never leak into it.
pub fn version_display() -> String {
    format_version_display(&version(), commit())
}

fn format_version_display(version: &str, commit: Option<&str>) -> String {
    match commit {
        Some(commit) => format!("{version} ({commit})"),
        None => version.to_string(),
    }
}

fn non_empty(value: Option<&'static str>) -> Option<&'static str> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn stable_version_defaults_to_cargo_version() {
        assert!(!super::version().is_empty());
    }

    #[test]
    fn version_display_appends_the_commit_only_when_present() {
        assert_eq!(
            super::format_version_display("0.8.0", Some("abc1234")),
            "0.8.0 (abc1234)"
        );
        assert_eq!(super::format_version_display("0.8.0", None), "0.8.0");
    }
}
