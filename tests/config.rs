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
        "PDS_ADMIN_PASSWORD",
        "PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX",
        "PDS_RECOVERY_DID_KEY",
        "PDS_DID_PLC_URL",
        "PDS_HOSTNAME",
        "PDS_INVITE_REQUIRED",
        "PDS_RATE_LIMITS_ENABLED",
        "PDS_RESERVED_HANDLES",
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

/// A rotation key, and the admin password beside it, which every start needs
/// and no test here is about.
const STARTABLE: [(&str, &str); 3] = [
    ("PDS_JWT_SECRET", "long enough to not be guessed"),
    ("PDS_ADMIN_PASSWORD", "hunter2"),
    (
        "PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX",
        "9085d2bef69286a6cbb51623c8fa258629945cd55ca705cc4e66700396894e0c",
    ),
];

/// The same, with these set over the top.
fn starting(vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
    let mut all = STARTABLE.to_vec();
    all.extend_from_slice(vars);
    with(&all)
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
    let error = starting(&[("PDS_INVITE_REQUIRED", "yes")]).expect_err("yes is not a boolean");
    assert!(
        matches!(error, ConfigError::NotABoolean("PDS_INVITE_REQUIRED")),
        "{error}"
    );
}

#[test]
fn both_spellings_of_each_boolean_are_read() {
    for (value, expected) in [("true", true), ("1", true), ("false", false), ("0", false)] {
        let config = starting(&[("PDS_INVITE_REQUIRED", value)]).expect("a configuration");
        assert_eq!(config.invite_required, expected, "{value}");
    }
}

#[test]
fn a_server_told_nothing_holds_callers_to_no_budget_and_asks_for_an_invite() {
    let config = starting(&[]).expect("a configuration");
    assert!(config.invite_required);
    assert!(!config.rate_limits);
    assert_eq!(config.hostname, "localhost");
    assert_eq!(config.port, 2583);
}

#[test]
fn a_secret_does_not_print_itself() {
    let config = starting(&[
        ("PDS_JWT_SECRET", "the one thing worth stealing"),
        ("PDS_RATE_LIMITS_ENABLED", "true"),
    ])
    .expect("a configuration");

    let printed = format!("{config:?}");
    assert!(!printed.contains("worth stealing"), "{printed}");
    assert!(!printed.contains("9085d2be"), "{printed}");
    assert_eq!(config.jwt_secret.reveal(), "the one thing worth stealing");
}

#[test]
fn a_secret_short_enough_to_be_found_by_trying_stops_the_server() {
    let error = starting(&[("PDS_JWT_SECRET", "hunter2")]).expect_err("a password, not a key");
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
    let config = starting(&[("PDS_JWT_SECRET", generated.reveal())]).expect("a configuration");
    assert_eq!(config.jwt_secret, generated);

    // And two of them differ, so the bytes are read rather than invented.
    assert_ne!(
        manapds::config::Secret::generate(),
        manapds::config::Secret::generate()
    );
}

#[test]
fn a_server_will_not_start_without_a_key_to_sign_operations_with() {
    let error = with(&[
        ("PDS_JWT_SECRET", "long enough to not be guessed"),
        ("PDS_ADMIN_PASSWORD", "hunter2"),
    ])
    .expect_err("no rotation key");
    assert!(
        matches!(
            error,
            ConfigError::Missing("PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX")
        ),
        "{error}"
    );
}

#[test]
fn a_rotation_key_that_is_not_one_stops_the_server() {
    for value in ["hunter2", "9085d2be", ""] {
        let error = starting(&[("PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX", value)])
            .expect_err("not a scalar on the curve");
        assert!(
            matches!(
                error,
                ConfigError::NotAKey("PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX")
                    | ConfigError::Missing("PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX")
            ),
            "{value}: {error}"
        );
    }

    let error = starting(&[("PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX", "hunter2")])
        .expect_err("not a key");
    assert!(
        error.to_string().contains("manapds rotation-key"),
        "the message has to name the fix: {error}"
    );
}

#[test]
fn a_recovery_key_is_read_as_the_did_key_it_is_written_as() {
    let config = starting(&[(
        "PDS_RECOVERY_DID_KEY",
        "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
    )])
    .expect("a configuration");
    assert_eq!(
        config.recovery_key.expect("a key").to_string(),
        "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"
    );

    let error = starting(&[("PDS_RECOVERY_DID_KEY", "did:key:nothing")])
        .expect_err("not a key anything could rotate to");
    assert!(
        matches!(error, ConfigError::NotADidKey("PDS_RECOVERY_DID_KEY")),
        "{error}"
    );
}

#[test]
fn the_public_url_is_https_unless_the_server_is_talking_to_itself() {
    let config = starting(&[]).expect("a configuration");
    assert_eq!(config.public_url(), "http://localhost:2583");

    let config = starting(&[("PDS_HOSTNAME", "pds.example.com")]).expect("a configuration");
    assert_eq!(config.public_url(), "https://pds.example.com");
    // And the handle domain follows the hostname, since one is the default of
    // the other.
    assert_eq!(config.handle_domains, [".pds.example.com"]);
}

#[test]
fn a_name_held_back_is_a_label_rather_than_a_handle() {
    let config = starting(&[("PDS_RESERVED_HANDLES", "mana, support ,help")]).expect("starts");
    assert_eq!(config.reserved_handles, ["mana", "support", "help"]);

    // A whole handle, and a list written with spaces instead of commas: both
    // are shapes this list never sees, and both would hold nothing back.
    for written in ["mana,admin.pds.test", "admin pds support"] {
        let error = starting(&[("PDS_RESERVED_HANDLES", written)]).expect_err("not a label");
        assert!(
            matches!(&error, ConfigError::NotALabel("PDS_RESERVED_HANDLES", _)),
            "{written}: {error}"
        );
    }
}

#[test]
fn holding_back_nothing_is_the_default() {
    let config = starting(&[]).expect("starts");
    assert!(config.reserved_handles.is_empty());
}
