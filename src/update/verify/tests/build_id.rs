//! Build ids that would name the updates directory's own layout.

use super::*;

/// On a case-insensitive filesystem (default macOS APFS) `PREVIOUS` names
/// `updates/previous`, so an apply into that build directory would remove
/// the rollback copy (#339-f4).
#[test]
fn manifest_with_a_build_id_that_is_a_layout_name_in_another_case_is_refused() {
    let primary = TestSigner::new(1);
    for build_id in ["PREVIOUS", "Previous", "State.json", "LOCK", "Guard.Log"] {
        let mut value: serde_json::Value =
            serde_json::from_str(&manifest_json(BUILD_ID, COMMIT, 1_800_000_000)).unwrap();
        value["build_id"] = build_id.into();
        let json = value.to_string();
        let minisig = primary.sign(json.as_bytes(), &comment(build_id, COMMIT));

        let err = verify_signed_manifest(json.as_bytes(), &minisig, &keys(&[&primary]))
            .err()
            .expect("the build id must be refused");
        assert_eq!(err.code(), "update_manifest_invalid", "{build_id:?}");
    }
    for build_id in [
        "2026-10-28-8a02b8342805",
        "Previously-1",
        "PREV",
        "v1.2_rc-3",
    ] {
        assert!(is_build_id(build_id), "{build_id:?}");
    }
}
