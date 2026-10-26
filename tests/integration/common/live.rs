//! Opt-in gate for the live (Postgres + SoftHSM) integration tests
//! (`est_serverkeygen_e2e`, `ca_grpc_audit_e2e`). Included with
//! `#[path = "common/live.rs"]` so tests that do not use it carry no dead code.
//!
//! - Without `OSTRICH_REQUIRE_LIVE_TESTS=1` an incomplete environment skips
//!   the test (passes, with a note on stderr).
//! - With `OSTRICH_REQUIRE_LIVE_TESTS=1` (CI) it panics instead: a
//!   green-but-skipped run is not evidence.
//! - [`assert_disposable_db`] refuses any database whose name has no `test`
//!   token (see [`is_disposable_db_name`]) before a table is cleared.
//!
//! Messages name the variable or tool, never its value (the URL may carry a
//! password; the PIN is a credential, even a throwaway one).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Testing), CA-2 (an opted-in run cannot
//!   pass by skipping)
//! - Test-safety guard (not an AU-9 control implementation): the destructive
//!   live suites never clear a database that is not named as a test database

use std::process::Command;

use ostrich_db::DatabasePool;

/// Set to `1` (CI) to turn a skipped live run into a failure.
pub const ENV_REQUIRE_LIVE: &str = "OSTRICH_REQUIRE_LIVE_TESTS";

/// The live-test variables, in the order [`decide`] receives them.
const VARS: [&str; 4] = [
    "DATABASE_URL",
    "PKCS11_MODULE_PATH",
    "PKCS11_SLOT",
    "PKCS11_PIN",
];

/// Live-test environment (the PIN is a throwaway SoftHSM test value). No
/// `Debug`: the URL and PIN must never reach a log.
pub struct LiveEnv {
    pub db_url: String,
    pub module: String,
    pub slot: u64,
    pub pin: String,
}

/// Outcome of the gate. No `Debug` (the `Run` variant carries the URL and PIN).
enum Decision {
    /// Run the live test.
    Run(LiveEnv),
    /// Skip (passes): reason for the stderr note.
    Skip(&'static str),
    /// Fail: reason for the panic message.
    Fail(&'static str),
}

/// Pure gate decision (same rules as `ostrich-ca`'s `live_test_env::decide`).
/// `vars` are the values of [`VARS`] in that order; `openssl` is whether
/// `openssl version` ran. Static reasons only, so no value can leak into a
/// message.
fn decide(require: bool, vars: [Option<&str>; 4], openssl: bool, needs_openssl: bool) -> Decision {
    let [db_url, module, slot, pin] = vars;
    let (Some(db_url), Some(module), Some(slot), Some(pin)) = (db_url, module, slot, pin) else {
        let reason = [
            (db_url, "DATABASE_URL is not set"),
            (module, "PKCS11_MODULE_PATH is not set"),
            (slot, "PKCS11_SLOT is not set"),
            (pin, "PKCS11_PIN is not set"),
        ]
        .into_iter()
        .find_map(|(v, reason)| v.is_none().then_some(reason))
        .unwrap_or("live-test environment is incomplete");
        return if require {
            Decision::Fail(reason)
        } else {
            Decision::Skip(reason)
        };
    };
    // A set-but-malformed slot is a configuration error either way.
    let Ok(slot) = slot.parse::<u64>() else {
        return Decision::Fail("PKCS11_SLOT must be numeric");
    };
    if needs_openssl && !openssl {
        return if require {
            Decision::Fail("the openssl binary is not available")
        } else {
            Decision::Skip("the openssl binary is not available")
        };
    }
    Decision::Run(LiveEnv {
        db_url: db_url.to_string(),
        module: module.to_string(),
        slot,
        pin: pin.to_string(),
    })
}

/// Read DATABASE_URL + PKCS11_MODULE_PATH + PKCS11_SLOT + PKCS11_PIN (and
/// check for `openssl` when `needs_openssl`). `None` = skip (only when
/// `OSTRICH_REQUIRE_LIVE_TESTS` is not `1`); panics on a required but
/// incomplete environment.
pub fn live_env(test: &str, needs_openssl: bool) -> Option<LiveEnv> {
    let require = std::env::var(ENV_REQUIRE_LIVE).as_deref() == Ok("1");
    let [a, b, c, d] = VARS.map(|v| std::env::var(v).ok());
    let openssl = needs_openssl
        && Command::new("openssl")
            .arg("version")
            .output()
            .is_ok_and(|o| o.status.success());
    let vars = [a.as_deref(), b.as_deref(), c.as_deref(), d.as_deref()];
    match decide(require, vars, openssl, needs_openssl) {
        Decision::Run(env) => Some(env),
        Decision::Skip(reason) => {
            eprintln!(
                "{test}: skipped ({reason}; set DATABASE_URL + PKCS11_MODULE_PATH + PKCS11_SLOT + \
                 PKCS11_PIN to run, {ENV_REQUIRE_LIVE}=1 to fail instead)"
            );
            None
        }
        Decision::Fail(reason) => panic!("{test}: live test required but {reason}"),
    }
}

/// Panic unless the connected database is a disposable test database
/// ([`is_disposable_db_name`]). Call before any DELETE.
///
/// Test-safety guard: never clear a database that is not named as a test
/// database.
pub async fn assert_disposable_db(pool: &DatabasePool, test: &str) {
    let name: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool.pool())
        .await
        .unwrap_or_else(|e| panic!("{test}: cannot read current_database(): {e}"));
    assert!(
        is_disposable_db_name(&name),
        "{test}: refusing to DELETE from database {name:?}: the database name must have a \
         `test` token (separated by `_`, `-` or `.`)"
    );
}

/// Whether `name` has a `_`/`-`/`.`-separated segment equal to `test`
/// (ASCII case-insensitive): `ostrich_pki_test`, `test`, `ostrich-test-db`
/// qualify; `ostrich_attestation`, `latest`, `contest_ca` do not. Same rule
/// in every copy of this guard.
fn is_disposable_db_name(name: &str) -> bool {
    name.split(['_', '-', '.'])
        .any(|segment| segment.eq_ignore_ascii_case("test"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "postgresql://u:secret-pw@h/ostrich_test";
    const PIN: &str = "9876-secret";
    const ALL: [Option<&str>; 4] = [Some(URL), Some("/m.so"), Some("7"), Some(PIN)];

    /// The reason of a skip or fail; `None` for a run.
    fn reason(d: &Decision) -> Option<&'static str> {
        match d {
            Decision::Skip(r) | Decision::Fail(r) => Some(r),
            Decision::Run(_) => None,
        }
    }

    #[test]
    fn missing_vars_skip_without_require() {
        for i in 0..4 {
            let mut vars = ALL;
            vars[i] = None;
            assert!(
                matches!(decide(false, vars, true, false), Decision::Skip(_)),
                "missing variable {i} must skip"
            );
        }
        assert!(matches!(
            decide(false, [None; 4], false, true),
            Decision::Skip(_)
        ));
    }

    #[test]
    fn missing_var_fails_under_require_and_names_it() {
        for (i, name) in VARS.iter().enumerate() {
            let mut vars = ALL;
            vars[i] = None;
            let d = decide(true, vars, true, true);
            assert!(matches!(d, Decision::Fail(_)), "{name} must fail");
            let r = reason(&d).unwrap_or_default();
            assert!(r.contains(name), "reason names {name}");
            assert!(!r.contains("secret"), "reason must not carry values");
        }
    }

    #[test]
    fn non_numeric_slot_fails_with_or_without_require() {
        let vars = [Some(URL), Some("/m.so"), Some("slot-x"), Some(PIN)];
        for require in [false, true] {
            let d = decide(require, vars, true, false);
            assert!(matches!(d, Decision::Fail(_)), "require={require}");
            assert_eq!(reason(&d), Some("PKCS11_SLOT must be numeric"));
        }
    }

    #[test]
    fn missing_openssl_skips_or_fails_only_when_needed() {
        assert!(matches!(decide(false, ALL, false, true), Decision::Skip(_)));
        let d = decide(true, ALL, false, true);
        assert!(matches!(d, Decision::Fail(_)));
        assert!(reason(&d).unwrap_or_default().contains("openssl"));
        assert!(matches!(decide(true, ALL, false, false), Decision::Run(_)));
    }

    #[test]
    fn complete_env_runs_with_parsed_slot() {
        for require in [false, true] {
            let Decision::Run(env) = decide(require, ALL, true, true) else {
                panic!("complete environment must run (require={require})");
            };
            assert_eq!(env.slot, 7);
            assert_eq!(env.module, "/m.so");
            assert!(env.db_url == URL && env.pin == PIN, "values passed through");
        }
    }

    #[test]
    fn disposable_db_name_requires_a_test_token() {
        for ok in [
            "ostrich_pki_test",
            "test",
            "ostrich-test-db",
            "TEST_db",
            "ci.Test",
        ] {
            assert!(is_disposable_db_name(ok), "{ok} must be accepted");
        }
        for bad in [
            "ostrich_attestation",
            "latest",
            "contest_ca",
            "ostrich_pki",
            "testing",
            "tests",
            "",
        ] {
            assert!(!is_disposable_db_name(bad), "{bad} must be refused");
        }
    }
}
