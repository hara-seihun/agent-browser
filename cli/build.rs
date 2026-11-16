use std::env;
use std::fs;
use std::path::Path;

/// Ensure `packages/dashboard/out/` exists so `rust-embed` doesn't fail during
/// Rust-only dev builds where the dashboard hasn't been built. The placeholder
/// `index.html` is only written when the directory is completely absent.
fn ensure_dashboard_dir() {
    let dashboard_out = Path::new("../packages/dashboard/out");
    println!("cargo:rerun-if-changed=../packages/dashboard/out");
    if !dashboard_out.join("index.html").exists() {
        let _ = fs::create_dir_all(dashboard_out);
        let _ = fs::write(
            dashboard_out.join("index.html"),
            "<!DOCTYPE html><html><body><p>Dashboard not built. Run: cd packages/dashboard &amp;&amp; pnpm build</p></body></html>\n",
        );
    }
}

/// The daemon identity is the package version plus the source commit, so a
/// rebuilt binary at the same package version still replaces daemons that
/// run older code. Builds outside a Git checkout (published npm sources)
/// use UPSTREAM_COMMIT when present or the supported explicit override;
/// npm sources without either retain the package version alone.
fn emit_daemon_build_identity() {
    let root = std::path::PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .to_path_buf();
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .current_dir(&root)
            // A caller may be operating a different repository. Identity belongs
            // to this source tree, never that caller's inherited Git context.
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .args(args)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
    };
    let version = env::var("CARGO_PKG_VERSION").unwrap();
    println!("cargo:rerun-if-env-changed=AGENT_BROWSER_SOURCE_COMMIT");
    // Relative metadata paths remain bound to the receiving checkout when a
    // Cargo cache is reused. Watching only absolute donor paths retains a stale
    // source stamp while recompiling new source in another checkout/worktree.
    if root.join(".git").is_file() {
        println!("cargo:rerun-if-changed=../.git");
    } else if root.join(".git").is_dir() {
        println!("cargo:rerun-if-changed=../.git/HEAD");
    }
    let own_git = git(&["rev-parse", "--show-toplevel"])
        .and_then(|path| std::fs::canonicalize(path).ok())
        == std::fs::canonicalize(&root).ok();
    let git_commit = if own_git {
        for path in ["HEAD", "packed-refs"] {
            if let Some(file) = git(&["rev-parse", "--git-path", path]) {
                let file = root.join(file);
                if file.exists() {
                    println!("cargo:rerun-if-changed={}", file.display());
                }
            }
        }
        if let Some(file) = git(&["rev-parse", "--symbolic-full-name", "HEAD"])
            .and_then(|reference| git(&["rev-parse", "--git-path", &reference]))
        {
            let file = root.join(file);
            if file.exists() {
                println!("cargo:rerun-if-changed={}", file.display());
            }
        }
        git(&["rev-parse", "HEAD"])
    } else {
        None
    };
    let snapshot = root.join("UPSTREAM_COMMIT");
    let snapshot_commit = if snapshot.is_file() {
        println!("cargo:rerun-if-changed=../UPSTREAM_COMMIT");
        std::fs::read_to_string(snapshot)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
    } else {
        None
    };
    let commit = env::var("AGENT_BROWSER_SOURCE_COMMIT")
        .ok()
        .filter(|commit| !commit.trim().is_empty())
        .or(git_commit)
        .or(snapshot_commit);
    let identity = commit
        .map(|commit| format!("{version}+{commit}"))
        .unwrap_or(version);
    println!("cargo:rustc-env=AGENT_BROWSER_DAEMON_BUILD={identity}");
}

fn main() {
    // Apply the fast linker only to this binary, not registry dependencies:
    // global rustflags would discard their reusable compiled artifacts.
    // Other platforms and hosts without mold keep their normal linker.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
        && env::var("TARGET").ok() == env::var("HOST").ok()
        && std::process::Command::new("mold")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    {
        println!("cargo:rustc-link-arg-bin=agent-browser=-fuse-ld=mold");
    }
    ensure_dashboard_dir();
    emit_daemon_build_identity();

}
