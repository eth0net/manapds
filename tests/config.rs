//! Configuration, which is read from the environment.
//!
//! A binary of its own, because the environment is process-wide: these tests
//! set variables that would otherwise reach every other test in the file.

use manapds::config::{Config, ConfigError};

/// Held for as long as the environment is being touched, since the test
/// runner would otherwise have several of these going at once.
static ENVIRONMENT: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Runs `from_env` with these variables set and nothing else of ours.
fn with(vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
    let _held = ENVIRONMENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for key in [
        "PDS_JWT_SECRET",
        "PDS_INVITE_REQUIRED",
        "PDS_RATE_LIMITS_ENABLED",
    ] {
        // Safe: this binary is single-threaded until a test spawns something,
        // and none of these do.
        unsafe { std::env::remove_var(key) };
    }
    for (key, value) in vars {
        unsafe { std::env::set_var(key, value) };
    }
    Config::from_env()
}

#[test]
fn a_server_will_not_start_without_a_secret_to_sign_sessions_under() {
    let error = with(&[]).expect_err("nothing to sign with");
    assert!(
        matches!(error, ConfigError::Missing("PDS_JWT_SECRET")),
        "{error}"
    );
}

#[test]
fn a_flag_that_is_neither_true_nor_false_stops_the_server() {
    let error = with(&[
        ("PDS_JWT_SECRET", "long enough to not be guessed"),
        ("PDS_INVITE_REQUIRED", "yes"),
    ])
    .expect_err("yes is not a boolean");
    assert!(
        matches!(error, ConfigError::NotABoolean("PDS_INVITE_REQUIRED")),
        "{error}"
    );
}

#[test]
fn both_spellings_of_each_boolean_are_read() {
    for (value, expected) in [("true", true), ("1", true), ("false", false), ("0", false)] {
        let config = with(&[
            ("PDS_JWT_SECRET", "long enough to not be guessed"),
            ("PDS_INVITE_REQUIRED", value),
        ])
        .expect("a configuration");
        assert_eq!(config.invite_required, expected, "{value}");
    }
}

#[test]
fn a_server_told_nothing_holds_callers_to_no_budget_and_asks_for_an_invite() {
    let config =
        with(&[("PDS_JWT_SECRET", "long enough to not be guessed")]).expect("a configuration");
    assert!(config.invite_required);
    assert!(!config.rate_limits);
    assert_eq!(config.hostname, "localhost");
    assert_eq!(config.port, 2583);
}

#[test]
fn a_secret_does_not_print_itself() {
    let config = with(&[
        ("PDS_JWT_SECRET", "the one thing worth stealing"),
        ("PDS_RATE_LIMITS_ENABLED", "true"),
    ])
    .expect("a configuration");

    let printed = format!("{config:?}");
    assert!(!printed.contains("worth stealing"), "{printed}");
    assert_eq!(config.jwt_secret.reveal(), "the one thing worth stealing");
}

#[test]
fn a_secret_short_enough_to_be_found_by_trying_stops_the_server() {
    let error = with(&[("PDS_JWT_SECRET", "hunter2")]).expect_err("a password, not a key");
    assert!(
        matches!(error, ConfigError::TooShort("PDS_JWT_SECRET", 24)),
        "{error}"
    );
    assert!(
        error.to_string().contains("manapds secret"),
        "the message has to name the fix: {error}"
    );
}

#[test]
fn a_generated_secret_clears_the_floor_it_is_measured_against() {
    let generated = manapds::config::Secret::generate();
    let config = with(&[("PDS_JWT_SECRET", generated.reveal())]).expect("a configuration");
    assert_eq!(config.jwt_secret, generated);

    // And two of them differ, so the bytes are read rather than invented.
    assert_ne!(
        manapds::config::Secret::generate(),
        manapds::config::Secret::generate()
    );
}
