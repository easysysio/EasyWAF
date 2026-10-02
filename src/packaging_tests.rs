// =========================================================
// packaging_tests.rs — EasyWAF
// packaging/service-account.sh, run against stand-ins for
// the commands it calls.
//
// The script runs as root while a package installs, which
// no test here can do. What can be checked is its decisions:
// what it creates when the account is or is not there, that
// a running service is stopped before the files change
// hands, and what it leaves alone when something fails. Each
// stand-in records how it was called and answers as the test
// tells it to.
// =========================================================

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// The stand-in commands and the redirected script, written once and shared:
/// every test runs the same files and differs only in what it tells them to
/// answer. (Written per test, a platform that inspects each new executable
/// on first run makes this the slowest thing in the suite.)
fn fixtures() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("easywaf-pkg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("bin")).unwrap();
        fs::create_dir_all(dir.join("data")).unwrap();
        fs::create_dir_all(dir.join("logs")).unwrap();

        let stub = |name: &str, answer: &str| {
            let path = dir.join("bin").join(name);
            fs::write(&path, format!("#!/bin/sh\necho \"{name} $*\" >> \"$STUB_LOG\"\n{answer}\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        };
        stub("getent", "case \"$1\" in\n  group)  [ -n \"$HAS_GROUP\" ] ;;\n  passwd) [ -n \"$HAS_USER\" ] ;;\nesac");
        stub("groupadd", "exit 0");
        stub("useradd", "[ -z \"$USERADD_FAILS\" ]");
        stub("chown", "exit 0");
        stub("systemctl", "case \"$1\" in\n  is-active) [ -n \"$ACTIVE\" ] ;;\n  start)     [ -z \"$START_FAILS\" ] ;;\n  *)         exit 0 ;;\nesac");

        // The script itself, with its two directories pointed into the test's
        // own: /opt/easywaf does not exist here, and must not be touched if it
        // does.
        let script = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/service-account.sh")).unwrap();
        let script = script
            .replace("DATA=/opt/easywaf", &format!("DATA={}", dir.join("data").display()))
            .replace("LOGS=/var/log/easywaf", &format!("LOGS={}", dir.join("logs").display()));
        assert!(!script.contains("=/opt/easywaf") && !script.contains("=/var/log/easywaf"),
                "the script's directories were not redirected");
        fs::write(dir.join("service-account.sh"), script).unwrap();
        dir
    })
}

/// A host as the script sees it: which commands exist and what they answer.
struct Host {
    /// Names this run, so tests running at once keep separate records.
    tag:     &'static str,
    env:     Vec<(&'static str, &'static str)>,
    /// A command this host does not have.
    missing: Option<&'static str>,
}

impl Host {
    /// A host with every command present, no account, and no service running.
    fn new(tag: &'static str) -> Self {
        Self { tag, env: Vec::new(), missing: None }
    }

    fn with(mut self, key: &'static str) -> Self {
        self.env.push((key, "1"));
        self
    }

    fn without_command(mut self, name: &'static str) -> Self {
        self.missing = Some(name);
        self
    }

    /// Run the script under `shell`. Returns whether it succeeded, the
    /// commands it called in order — look-ups left out — and what it said on
    /// stderr.
    fn run(&self, shell: &str) -> (bool, Vec<String>, String) {
        let dir = fixtures();
        let log = dir.join(format!("{}.log", self.tag));
        let _ = fs::remove_file(&log);

        // Every command, or every command but one: links to the shared
        // stand-ins, in a directory of this host's own.
        let bin = match self.missing {
            None => dir.join("bin"),
            Some(missing) => {
                let own = dir.join(format!("bin-{}", self.tag));
                let _ = fs::remove_dir_all(&own);
                fs::create_dir_all(&own).unwrap();
                for entry in fs::read_dir(dir.join("bin")).unwrap().flatten() {
                    if entry.file_name() != missing {
                        std::os::unix::fs::symlink(entry.path(), own.join(entry.file_name())).unwrap();
                    }
                }
                own
            }
        };

        let out = Command::new(shell)
            .arg(dir.join("service-account.sh"))
            .env_clear()
            .env("PATH", bin)
            .env("STUB_LOG", &log)
            .envs(self.env.iter().copied())
            .output()
            .unwrap();
        let calls = fs::read_to_string(&log).unwrap_or_default()
            .lines()
            .filter(|l| !l.starts_with("getent "))
            .map(|l| l.split_whitespace().take(2).collect::<Vec<_>>().join(" "))
            .collect();
        (out.status.success(), calls, String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

/// The shells a package script meets: Debian's /bin/sh is dash, most others'
/// is bash.
fn shells() -> Vec<&'static str> {
    ["/bin/sh", "/bin/dash", "/bin/bash"].into_iter().filter(|s| Path::new(s).exists()).collect()
}

fn position(calls: &[String], call: &str) -> usize {
    calls.iter().position(|c| c == call)
        .unwrap_or_else(|| panic!("{call:?} was not called; calls were {calls:?}"))
}

#[test]
fn a_first_install_creates_the_group_and_the_account() {
    for shell in shells() {
        let (ok, calls, _) = Host::new("first").run(shell);
        assert!(ok, "{shell}");
        assert!(position(&calls, "groupadd --system") < position(&calls, "useradd --system"), "{shell}: {calls:?}");
        assert!(calls.contains(&"chown -hR".to_string()), "{shell}: {calls:?}");
        // Nothing was running, so nothing is stopped and nothing is started.
        assert!(!calls.iter().any(|c| c == "systemctl stop" || c == "systemctl start"), "{shell}: {calls:?}");
    }
}

#[test]
fn an_upgrade_that_finds_the_account_creates_nothing() {
    for shell in shells() {
        let (ok, calls, _) = Host::new("upgrade").with("HAS_GROUP").with("HAS_USER").with("ACTIVE").run(shell);
        assert!(ok, "{shell}");
        assert!(!calls.iter().any(|c| c.starts_with("groupadd") || c.starts_with("useradd")), "{shell}: {calls:?}");
    }
}

#[test]
fn whichever_half_of_the_account_is_missing_is_the_half_created() {
    for shell in shells() {
        let (_, calls, _) = Host::new("user-only").with("HAS_GROUP").run(shell);
        assert!(calls.iter().any(|c| c.starts_with("useradd")), "{shell}: {calls:?}");
        assert!(!calls.iter().any(|c| c.starts_with("groupadd")), "{shell}: {calls:?}");

        let (_, calls, _) = Host::new("group-only").with("HAS_USER").run(shell);
        assert!(calls.iter().any(|c| c.starts_with("groupadd")), "{shell}: {calls:?}");
        assert!(!calls.iter().any(|c| c.starts_with("useradd")), "{shell}: {calls:?}");
    }
}

/// A service still running as root would otherwise create files after they
/// were handed over, which the account then cannot open.
#[test]
fn a_running_service_is_stopped_before_its_files_change_hands() {
    for shell in shells() {
        let (ok, calls, _) = Host::new("order").with("ACTIVE").run(shell);
        assert!(ok, "{shell}");
        let (stop, chown, start) = (
            position(&calls, "systemctl stop"),
            position(&calls, "chown -hR"),
            position(&calls, "systemctl start"),
        );
        assert!(position(&calls, "useradd --system") < stop, "the account comes first: {calls:?}");
        assert!(stop < chown && chown < start, "{shell}: {calls:?}");
        assert_eq!(calls.iter().filter(|c| *c == "chown -hR").count(), 2, "data and logs: {calls:?}");
    }
}

#[test]
fn a_host_where_the_account_cannot_be_made_keeps_its_service_running() {
    for shell in shells() {
        let (ok, calls, said) = Host::new("no-account").with("ACTIVE").with("USERADD_FAILS").run(shell);
        assert!(!ok, "{shell}: it must say it failed");
        assert!(said.contains("could not create the account"), "{shell}: {said}");
        assert!(!calls.iter().any(|c| c.starts_with("systemctl") || c.starts_with("chown")), "{shell}: {calls:?}");

        let (ok, calls, said) = Host::new("no-useradd").with("ACTIVE").without_command("useradd").run(shell);
        assert!(!ok, "{shell}");
        assert!(said.contains("useradd is not installed"), "{shell}: {said}");
        assert!(!calls.iter().any(|c| c.starts_with("systemctl") || c.starts_with("chown")), "{shell}: {calls:?}");
    }
}

#[test]
fn a_service_that_does_not_come_back_is_reported_and_the_install_still_succeeds() {
    for shell in shells() {
        let (ok, _, said) = Host::new("no-start").with("ACTIVE").with("START_FAILS").run(shell);
        assert!(ok, "{shell}: the package is installed either way");
        assert!(said.contains("did not start again"), "{shell}: {said}");
    }
}

#[test]
fn a_host_without_systemd_still_gets_the_account_and_its_files() {
    for shell in shells() {
        let (ok, calls, _) = Host::new("no-systemd").without_command("systemctl").run(shell);
        assert!(ok, "{shell}");
        assert!(calls.contains(&"useradd --system".to_string()), "{shell}: {calls:?}");
        assert!(calls.contains(&"chown -hR".to_string()), "{shell}: {calls:?}");
    }
}

/// Both packages must run the script, and ship it where they run it from.
#[test]
fn both_packages_ship_the_script_and_run_it() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cargo = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let postinst = fs::read_to_string(root.join("packaging/deb/postinst")).unwrap();
    const INSTALLED: &str = "/usr/lib/easywaf/service-account";

    assert!(postinst.contains(INSTALLED), "the Debian postinst does not run it");
    assert_eq!(cargo.matches(&format!("\"{INSTALLED}\"")).count(), 2,
               "it should be an asset of the .deb and of the .rpm");
    let rpm = cargo.split("[package.metadata.generate-rpm]").nth(1).unwrap();
    let post = rpm.split("post_install_script").nth(1).unwrap().split("\"\"\"").nth(1).unwrap();
    assert!(post.contains(INSTALLED), "the RPM's post-install script does not run it");

    let mode = fs::metadata(root.join("packaging/service-account.sh")).unwrap().permissions().mode();
    assert_eq!(mode & 0o111, 0o111, "the script is not executable in the repository");
}
