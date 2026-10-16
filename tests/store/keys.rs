//! The signing key, which is a file rather than a row.

use manapds::store::keys;

use super::*;

#[test]
fn a_signing_key_survives_the_file_it_is_kept_in() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = Directory::new(home.path()).actor_key(&account());
    let keypair = Keypair::generate(Algorithm::Secp256k1);

    keys::write(&path, &keypair).expect("writes");
    let read = keys::read(&path).expect("reads");
    assert_eq!(read.public_key(), keypair.public_key());

    // The reference writes 32 raw bytes and nothing else.
    assert_eq!(std::fs::read(&path).expect("reads").len(), 32);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("reads")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "nobody else reads a signing key");
    }
}

#[test]
fn a_signing_key_is_never_written_over() {
    let home = tempfile::tempdir().expect("a temporary directory");
    let path = home
        .path()
        .join("actors")
        .join("aa")
        .join("did")
        .join("key");
    let keypair = Keypair::generate(Algorithm::Secp256k1);
    keys::write(&path, &keypair).expect("writes");

    let second = Keypair::generate(Algorithm::Secp256k1);
    keys::write(&path, &second).expect_err("a key is written once");
    assert_eq!(
        keys::read(&path).expect("reads").to_bytes(),
        keypair.to_bytes()
    );
}
