//! CAR files, against one the reference wrote.

use std::{fs, path::Path};

use base64::Engine as _;
use manapds::repo::{BlockMap, Cid, Error, Store, car, cid_for};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    root: String,
    blocks: Vec<Block>,
    car: String,
}

#[derive(Deserialize)]
struct Block {
    cid: String,
    bytes: String,
}

#[test]
fn reads_what_the_reference_wrote() {
    for fixture in fixtures() {
        let (root, blocks) = car::read(&base64(&fixture.car)).expect("reads");
        assert_eq!(root.to_string(), fixture.root);
        assert_eq!(blocks.len(), fixture.blocks.len());
        for block in &fixture.blocks {
            let cid: Cid = block.cid.parse().expect("a CID");
            assert_eq!(
                blocks.get(&cid).as_deref(),
                Ok(base64(&block.bytes).as_slice())
            );
        }
    }
}

#[test]
fn writes_a_file_the_same_size_with_the_same_header() {
    for fixture in fixtures() {
        let reference = base64(&fixture.car);
        let (root, blocks) = car::read(&reference).expect("reads");
        let written = car::write(root, &blocks).expect("writes");

        // Which order blocks come in is the writer's to choose, so the header
        // is what has to match byte for byte and the rest has to survive a
        // round trip.
        let header = 1 + usize::from(reference[0]);
        assert_eq!(&written[..header], &reference[..header]);
        assert_eq!(written.len(), reference.len());
        assert_eq!(car::read(&written), Ok((root, blocks)));
    }
}

#[test]
fn a_block_under_the_wrong_cid_is_refused() {
    let cid = cid_for(b"\xa0");
    let mut blocks = BlockMap::new();
    blocks.insert(cid, b"\xa1\x61a\x01".to_vec());
    let car = car::write(cid, &blocks).expect("writes");

    assert_eq!(car::read(&car), Err(Error::WrongCid(cid)));
}

#[test]
fn a_truncated_file_is_refused() {
    let car = base64(&fixtures()[0].car);
    let cut = &car[..car.len() - 1];

    assert!(matches!(car::read(cut), Err(Error::MalformedCar(_))));
}

fn fixtures() -> Vec<Fixture> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/car/car-file-fixtures.json");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).expect("fixtures")
}

fn base64(input: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(input)
        .expect("base64")
}
