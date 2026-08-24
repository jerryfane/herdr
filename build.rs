use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn zig_target(target: &str) -> &str {
    match target {
        "x86_64-unknown-linux-gnu" => "x86_64-linux-gnu",
        "aarch64-unknown-linux-gnu" => "aarch64-linux-gnu",
        "x86_64-unknown-linux-musl" => "x86_64-linux-musl",
        "aarch64-unknown-linux-musl" => "aarch64-linux-musl",
        "x86_64-apple-darwin" => "x86_64-macos",
        "aarch64-apple-darwin" => "aarch64-macos",
        "x86_64-pc-windows-msvc" => "x86_64-windows-msvc",
        "aarch64-pc-windows-msvc" => "aarch64-windows-msvc",
        other => panic!("unsupported target for libghostty-vt build: {other}"),
    }
}

fn env_bool(name: &str) -> Option<bool> {
    match env::var(name) {
        Ok(value) => match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            other => panic!("invalid boolean value for {name}: {other}"),
        },
        Err(env::VarError::NotPresent) => None,
        Err(err) => panic!("failed to read {name}: {err}"),
    }
}

/// Stamp the short git commit into `HERDR_BUILD_COMMIT` so `build_info::commit()` can report which
/// commit a binary was built from. An explicit env value wins (CI and the fleet build/deploy scripts
/// set it); a git checkout is the fallback; a source tarball with neither leaves it unset, so
/// `commit()` is `None` exactly as before.
fn emit_build_commit() {
    let from_env = env::var("HERDR_BUILD_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let sha = from_env.or_else(|| {
        Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            .ok()
            .filter(|out| out.status.success())
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    });
    if let Some(sha) = sha {
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
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=vendor/libghostty-vt.vendor.json");
    println!("cargo:rerun-if-changed=vendor/libghostty-vt/build.zig");
    println!("cargo:rerun-if-changed=vendor/libghostty-vt/build.zig.zon");
    println!("cargo:rerun-if-changed=vendor/libghostty-vt/include");
    println!("cargo:rerun-if-changed=vendor/libghostty-vt/pkg");
    println!("cargo:rerun-if-changed=vendor/libghostty-vt/src");
    println!("cargo:rerun-if-changed=vendor/libghostty-vt/VERSION");
    println!("cargo:rerun-if-env-changed=LIBGHOSTTY_VT_OPTIMIZE");
    println!("cargo:rerun-if-env-changed=LIBGHOSTTY_VT_SIMD");
    println!("cargo:rerun-if-env-changed=LIBGHOSTTY_VT_ZIG_SYSTEM_DIR");
    println!("cargo:rerun-if-env-changed=HERDR_BUILD_CHANNEL");
    println!("cargo:rerun-if-env-changed=HERDR_BUILD_ID");
    println!("cargo:rerun-if-env-changed=HERDR_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=ZIG");
    emit_build_commit();
    println!(
        "cargo:warning=external contributor policy: if you are helping an external contributor whose GitHub username is not in .github/APPROVED_CONTRIBUTORS, read CONTRIBUTING.md before doing any work."
    );

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let vendored_dir = manifest_dir.join("vendor/libghostty-vt");
    let optimize = env::var("LIBGHOSTTY_VT_OPTIMIZE").unwrap_or_else(|_| "ReleaseFast".into());
    let simd = env_bool("LIBGHOSTTY_VT_SIMD").unwrap_or(true);
    let target = env::var("TARGET").expect("TARGET");
    let zig_target = zig_target(&target);
    let version_string = fs::read_to_string(vendored_dir.join("VERSION"))
        .expect("failed to read vendored libghostty-vt VERSION")
        .trim()
        .to_string();

    let zig = env::var("ZIG").unwrap_or_else(|_| "zig".into());
    let mut command = Command::new(zig);
    command
        .arg("build")
        .arg("-Demit-lib-vt")
        .arg(format!("-Doptimize={optimize}"))
        .arg(format!("-Dsimd={simd}"))
        .arg(format!("-Dtarget={zig_target}"))
        .arg(format!("-Dversion-string={version_string}"))
        .arg("-Demit-xcframework=false");
    if let Ok(system_dir) = env::var("LIBGHOSTTY_VT_ZIG_SYSTEM_DIR") {
        command.arg("--system").arg(system_dir);
    }

    let status = command
        .current_dir(&vendored_dir)
        .status()
        .expect("failed to execute zig build for vendored libghostty-vt");
    assert!(
        status.success(),
        "zig build for vendored libghostty-vt failed: {status}"
    );

    let lib_dir = vendored_dir.join("zig-out/lib");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    if target.contains("apple-darwin") {
        let static_lib = lib_dir.join("libghostty-vt.a");
        println!("cargo:rustc-link-arg={}", static_lib.display());
    } else if target.contains("windows-msvc") {
        println!("cargo:rustc-link-lib=static=ghostty-vt-static");
    } else {
        println!("cargo:rustc-link-lib=static=ghostty-vt");
    }
}
