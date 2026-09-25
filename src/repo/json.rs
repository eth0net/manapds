//! A record as JSON, which is the only shape a client ever sees it in.
//!
//! dag-cbor holds two things JSON has no syntax for, so the lexicons give each
//! one an object with a single reserved key: `$link` for a CID and `$bytes`
//! for a byte string. Everything else maps across as itself.

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD as BASE64};
use ipld_core::ipld::Ipld;
use serde_json::{Map, Value};

use super::Error;

/// The key a CID is written under.
const LINK: &str = "$link";

/// The key a byte string is written under.
const BYTES: &str = "$bytes";

/// A record as a client is shown it.
///
/// # Errors
///
/// If it holds a number the data model has no room for, which is a block
/// written by something that was not this server.
pub fn to_json(value: &Ipld) -> Result<Value, Error> {
    Ok(match value {
        Ipld::Null => Value::Null,
        Ipld::Bool(held) => Value::Bool(*held),
        Ipld::Integer(held) => Value::from(
            i64::try_from(*held).map_err(|_| Error::NotRecordData("an integer past 64 bits"))?,
        ),
        Ipld::Float(_) => return Err(Error::NotRecordData("a float")),
        Ipld::String(held) => Value::String(held.clone()),
        Ipld::Bytes(held) => tagged(BYTES, BASE64.encode(held)),
        Ipld::List(held) => Value::Array(held.iter().map(to_json).collect::<Result<_, _>>()?),
        Ipld::Map(held) => Value::Object(
            held.iter()
                .map(|(key, held)| Ok((key.clone(), to_json(held)?)))
                .collect::<Result<_, Error>>()?,
        ),
        Ipld::Link(held) => tagged(LINK, held.to_string()),
    })
}

/// A record as a client wrote it.
///
/// # Errors
///
/// If it holds a number the data model has no room for, or a `$link` that is
/// not a CID.
pub fn from_json(value: Value) -> Result<Ipld, Error> {
    Ok(match value {
        Value::Null => Ipld::Null,
        Value::Bool(held) => Ipld::Bool(held),
        Value::Number(held) => Ipld::Integer(
            held.as_i64()
                .ok_or(Error::NotRecordData("a number that is not an integer"))?
                .into(),
        ),
        Value::String(held) => Ipld::String(held),
        Value::Array(held) => {
            Ipld::List(held.into_iter().map(from_json).collect::<Result<_, _>>()?)
        }
        Value::Object(held) => match reserved(&held) {
            Some((LINK, Value::String(cid))) => Ipld::Link(
                cid.parse()
                    .map_err(|_| Error::NotRecordData("a $link that is not a CID"))?,
            ),
            Some((BYTES, Value::String(bytes))) => Ipld::Bytes(
                BASE64
                    .decode(bytes)
                    .map_err(|_| Error::NotRecordData("a $bytes that is not base64"))?,
            ),
            Some(_) => return Err(Error::NotRecordData("a $link or $bytes holding no string")),
            None => Ipld::Map(
                held.into_iter()
                    .map(|(key, held)| Ok((key, from_json(held)?)))
                    .collect::<Result<_, Error>>()?,
            ),
        },
    })
}

/// An object standing for one of the two things JSON cannot write, which is
/// what an object of exactly one reserved key means.
fn reserved(object: &Map<String, Value>) -> Option<(&'static str, &Value)> {
    if object.len() != 1 {
        return None;
    }
    [LINK, BYTES]
        .into_iter()
        .find_map(|key| object.get(key).map(|held| (key, held)))
}

/// One of those two, written back out.
fn tagged(key: &str, held: String) -> Value {
    Value::Object(Map::from_iter([(key.to_owned(), Value::String(held))]))
}
