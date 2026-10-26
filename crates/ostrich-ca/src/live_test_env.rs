//! Shared opt-in gate for the live (Postgres + SoftHSM) e2e test modules
//! (`audit_signing_e2e`, `crl_delta_e2e`, `issuance_aia_e2e`, `pop_e2e`).
//!
//! - Without `OSTRICH_REQUIRE_LIVE_TESTS=1` a test whose environment is
//!   incomplete is skipped (passes, with a note on stderr), so the normal
//!   `cargo test` run is unaffected.
//! - With `OSTRICH_REQUIRE_LIVE_TESTS=1` a missing variable, a non-numeric
//!   slot or a missing `openssl` binary FAILS the test: a CI job that
//!   silently skipped would be a green run with no evidence behind it.
//! - Before any `DELETE`, [`assert_disposable_db`] requires a `test` token in
//!   the database name ([`is_disposable_db_name`]), so these tests never wipe
//!   a database that is not named as a test database.
//!
//! Failure messages name the variable or tool, never its value (the
//! database URL and PIN must not reach test logs).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Testing), CA-2 (assessment evidence: an
//!   opted-in run cannot pass by skipping)
//! - Test-safety guard (not an AU-9 control implementation): the destructive
//!   live modules never clear a database that is not named as a test database

use std::process::Command;

use ostrich_db::DatabasePool;

/// Set to `1` to turn a skipped live test into a failure (CI).
pub(crate) const ENV_REQUIRE_LIVE: &str = "OSTRICH_REQUIRE_LIVE_TESTS";

/// The live-test variables, in the order [`decide`] receives them.
const VARS: [&str; 4] = [
    "DATABASE_URL",
    "PKCS11_MODULE_PATH",
    "PKCS11_SLOT",
    "PKCS11_PIN",
];

/// Live-test environment. The PIN is a throwaway SoftHSM test value (the
/// PKCS#11 provider takes `&str`).
pub(crate) struct LiveEnv {
    pub db_url: String,
    pub module: String,
    pub slot: u64,
    pub pin: String,
}

// NIST 800-53: SI-11 / SI-12 (test code) - the URL (may carry a password) and
// the PIN are never Debug-printed, even in a test panic.
impl std::fmt::Debug for LiveEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveEnv")
            .field("db_url", &"<redacted>")
            .field("module", &self.module)
            .field("slot", &self.slot)
            .field("pin", &"<redacted>")
            .finish()
    }
}

/// Outcome of the gate.
#[derive(Debug)]
pub(crate) enum Decision {
    /// Run the live test.
    Run(LiveEnv),
    /// Skip (passes): reason for the stderr note.
    Skip(&'static str),
    /// Fail: reason for the panic message.
    Fail(&'static str),
}

/// Pure gate decision. `vars` are the values of [`VARS`] (in that order),
/// `openssl` whether `openssl version` ran. Static reasons only, so no
/// value can leak into a message.
pub(crate) fn decide(
    require: bool,
    vars: [Option<&str>; 4],
    openssl: bool,
    needs_openssl: bool,
) -> Decision {
    let [db_url, module, slot, pin] = vars;
    let missing = [
        (db_url, "DATABASE_URL is not set"),
        (module, "PKCS11_MODULE_PATH is not set"),
        (slot, "PKCS11_SLOT is not set"),
        (pin, "PKCS11_PIN is not set"),
    ]
    .into_iter()
    .find_map(|(v, reason)| v.is_none().then_some(reason));
    if let Some(reason) = missing {
        return if require {
            Decision::Fail(reason)
        } else {
            Decision::Skip(reason)
        };
    }
    let (Some(db_url), Some(module), Some(slot), Some(pin)) = (db_url, module, slot, pin) else {
        return Decision::Fail("live-test environment is incomplete");
    };
    // A set-but-malformed slot is a configuration error either way (the
    // modules panicked on parse before this gate existed).
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

/// Read the live-test environment for `test`. `None` = skip (only when
/// `OSTRICH_REQUIRE_LIVE_TESTS` is not `1`); panics on a required but
/// incomplete environment.
pub(crate) fn live_env(test: &str, needs_openssl: bool) -> Option<LiveEnv> {
    let require = std::env::var(ENV_REQUIRE_LIVE).as_deref() == Ok("1");
    let values: Vec<Option<String>> = VARS.iter().map(|v| std::env::var(v).ok()).collect();
    let vars: [Option<&str>; 4] = std::array::from_fn(|i| values[i].as_deref());
    let openssl = needs_openssl
        && Command::new("openssl")
            .arg("version")
            .output()
            .is_ok_and(|o| o.status.success());
    match decide(require, vars, openssl, needs_openssl) {
        Decision::Run(env) => Some(env),
        Decision::Skip(reason) => {
            eprintln!(
                "{test}: skipped ({reason}; set DATABASE_URL + PKCS11_MODULE_PATH + PKCS11_SLOT \
                 + PKCS11_PIN to run, {ENV_REQUIRE_LIVE}=1 to fail instead)"
            );
            None
        }
        Decision::Fail(reason) => panic!("{test}: live test required but {reason}"),
    }
}

/// Panic unless the connected database is a disposable test database
/// ([`is_disposable_db_name`]). Call before any `DELETE` (test-safety guard).
pub(crate) async fn assert_disposable_db(pool: &DatabasePool, test: &str) {
    let name: String = match sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool.pool())
        .await
    {
        Ok(name) => name,
        Err(e) => panic!("{test}: cannot read current_database(): {e}"),
    };
    assert!(
        is_disposable_db_name(&name),
        "{test}: refusing to DELETE from database {name:?}: the database name must have a \
         `test` token (separated by `_`, `-` or `.`)"
    );
}

/// Whether `name` has a `_`/`-`/`.`-separated segment equal to `test`
/// (ASCII case-insensitive): `ostrich_pki_test`, `test`, `ostrich-test-db`
/// qualify; `ostrich_attestation`, `latest`, `contest_ca` do not. Same rule
/// in every copy of this guard (`tests/integration/common/live.rs`,
/// `ostrich-db` example `migrate_test_db`, `ostrich-audit` `tests/common`).
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

    fn reason(d: &Decision) -> &'static str {
        match d {
            Decision::Skip(r) | Decision::Fail(r) => r,
            Decision::Run(_) => panic!("expected skip/fail, got run"),
        }
    }

    #[test]
    fn missing_vars_skip_without_require() {
        for i in 0..4 {
            let mut vars = ALL;
            vars[i] = None;
            let d = decide(false, vars, true, false);
            assert!(matches!(d, Decision::Skip(_)), "var {i}: {d:?}");
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
            assert!(matches!(d, Decision::Fail(_)), "{name}: {d:?}");
            let r = reason(&d);
            assert!(r.contains(name), "reason names {name}: {r}");
            assert!(!r.contains("secret"), "reason must not carry values");
        }
    }

    #[test]
    fn non_numeric_slot_fails_with_or_without_require() {
        let vars = [Some(URL), Some("/m.so"), Some("slot-x"), Some(PIN)];
        for require in [false, true] {
            let d = decide(require, vars, true, false);
            assert_eq!(reason(&d), "PKCS11_SLOT must be numeric");
            assert!(matches!(d, Decision::Fail(_)));
        }
    }

    #[test]
    fn missing_openssl_skips_or_fails() {
        assert!(matches!(decide(false, ALL, false, true), Decision::Skip(_)));
        let d = decide(true, ALL, false, true);
        assert!(matches!(d, Decision::Fail(_)));
        assert!(reason(&d).contains("openssl"));
        // Not needed: openssl absence is irrelevant.
        assert!(matches!(decide(true, ALL, false, false), Decision::Run(_)));
    }

    #[test]
    fn complete_env_runs_with_parsed_slot() {
        let Decision::Run(env) = decide(true, ALL, true, true) else {
            panic!("expected run");
        };
        assert_eq!(env.slot, 7);
        assert_eq!(env.module, "/m.so");
        assert_eq!(env.db_url, URL);
        assert_eq!(env.pin, PIN);
        let Decision::Run(_) = decide(false, ALL, true, true) else {
            panic!("expected run");
        };
    }

    #[test]
    fn debug_redacts_url_and_pin() {
        let Decision::Run(env) = decide(false, ALL, true, false) else {
            panic!("expected run");
        };
        let s = format!("{env:?}");
        assert!(!s.contains("secret"), "{s}");
        assert!(s.contains("<redacted>"));
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
