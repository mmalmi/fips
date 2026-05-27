use std::process::Command;

fn git_output(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

fn main() {
    // Git commit hash (short)
    let git_hash = git_output(&["rev-parse", "--short=10", "HEAD"]).unwrap_or_default();
    println!("cargo:rustc-env=FIPS_GIT_HASH={git_hash}");

    // Dirty working tree
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    if dirty {
        println!("cargo:rustc-env=FIPS_GIT_DIRTY=-dirty");
    } else {
        println!("cargo:rustc-env=FIPS_GIT_DIRTY=");
    }

    // Build target triple
    if let Ok(target) = std::env::var("TARGET") {
        println!("cargo:rustc-env=FIPS_TARGET={target}");
    }

    // Rebuild when the checked-out commit changes. Do not watch the whole refs
    // tree: routine `git fetch` updates unrelated refs and should not invalidate
    // Cargo's cache for dependents.
    if let Some(head_path) = git_output(&["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={head_path}");
    } else {
        println!("cargo:rerun-if-changed=.git/HEAD");
    }
    if let Some(head_ref) = git_output(&["symbolic-ref", "--quiet", "HEAD"])
        && let Some(head_ref_path) = git_output(&["rev-parse", "--git-path", &head_ref])
    {
        println!("cargo:rerun-if-changed={head_ref_path}");
    }

    // Support reproducible builds (Debian packaging)
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    // bluer/BlueZ is glibc-linux only: musl cross-compiles (OpenWrt) can't
    // satisfy libdbus-sys's pkg-config cross-compile requirement, and musl
    // router targets don't run BlueZ by default anyway.
    println!("cargo:rustc-check-cfg=cfg(bluer_available)");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "linux" && target_env != "musl" {
        println!("cargo:rustc-cfg=bluer_available");
    }
}
