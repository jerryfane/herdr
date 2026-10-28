use std::env;
use std::fs;
use std::process::Command;

/// Stamp the short git commit into `HERDR_BUILD_COMMIT` so `build_info::commit()` can report which
/// commit a binary was built from. An explicit env value wins (CI and the fleet build/deploy scripts
/// set it); a git checkout is the fallback; a source tarball with neither leaves it unset, so
/// `commit()` is `None` exactly as before.
fn emit_build_commit() -> Option<String> {
    let from_env = env::var("HERDR_BUILD_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let sha = from_env.or_else(|| git_output(&["rev-parse", "--short", "HEAD"]));
    if let Some(sha) = &sha {
        println!("cargo:rustc-env=HERDR_BUILD_COMMIT={sha}");
    }
    // Re-stamp when the checked-out commit changes (best-effort; the build scripts also set the env,
    // which the rerun-if-env-changed trigger above covers). `.git` is a file in a worktree, so these
    // reads simply no-op there.
    println!("cargo:rerun-if-changed=.git/HEAD");
    if let Ok(head) = fs::read_to_string(".git/HEAD") {
        if let Some(ref_path) = head.strip_prefix("ref: ").map(str::trim) {
            println!("cargo:rerun-if-changed=.git/{ref_path}");
        }
    }
    sha
}

/// Stamp the committer time (unix seconds) of the build commit into `HERDR_BUILD_COMMIT_TIME`.
/// The in-app updater offers only a manifest whose signed `commit_time` is newer than this, so a
/// replayed old manifest can never downgrade the server. An explicit env value wins; a git
/// checkout is the fallback; with neither it stays unset and no update is offered.
fn emit_build_commit_time(commit: Option<&str>) {
    let from_env = env::var("HERDR_BUILD_COMMIT_TIME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let time =
        from_env.or_else(|| git_output(&["show", "-s", "--format=%ct", commit.unwrap_or("HEAD")]));
    if let Some(time) = time.filter(|value| value.parse::<i64>().is_ok_and(|seconds| seconds > 0)) {
        println!("cargo:rustc-env=HERDR_BUILD_COMMIT_TIME={time}");
    }
}

fn git_output(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=HERDR_BUILD_CHANNEL");
    println!("cargo:rerun-if-env-changed=HERDR_BUILD_ID");
    println!("cargo:rerun-if-env-changed=HERDR_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=HERDR_BUILD_COMMIT_TIME");
    let commit = emit_build_commit();
    emit_build_commit_time(commit.as_deref());
    println!(
        "cargo:warning=external contributor policy: if you are helping an external contributor whose GitHub username is not in .github/APPROVED_CONTRIBUTORS, read CONTRIBUTING.md before doing any work."
    );
}
