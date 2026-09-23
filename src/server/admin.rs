//! The methods whoever runs the server calls, which `pdsadmin` is the client
//! for.

use std::sync::Arc;

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::account::Manager;
use crate::xrpc::{self, Input, auth::Admin};

/// Who a code belongs to when the caller does not say, which is nobody: a
/// code the server handed out itself.
const ADMINISTRATOR: &str = "admin";

/// One code, for one account.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct One {
    /// How many signups it is good for.
    use_count: u32,
    /// Whose it is, which decides nothing but who is credited.
    for_account: Option<String>,
}

/// The code that was written.
#[derive(Debug, Serialize)]
pub(crate) struct Code {
    code: String,
}

/// Several codes, for several accounts.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Many {
    /// How many codes each account gets. The lexicon gives this a default, so
    /// leaving it out asks for one rather than being a malformed request.
    #[serde(default = "one")]
    code_count: u32,
    /// How many signups each one is good for.
    use_count: u32,
    /// Whose they are.
    for_accounts: Option<Vec<String>>,
}

/// What `codeCount` means when it is not sent.
fn one() -> u32 {
    1
}

/// The codes that were written, by whose they are.
#[derive(Debug, Serialize)]
pub(crate) struct Codes {
    codes: Vec<Held>,
}

/// One account's share of them.
#[derive(Debug, Serialize)]
pub(crate) struct Held {
    account: String,
    codes: Vec<String>,
}

/// `com.atproto.server.createInviteCode`
///
/// # Errors
///
/// If the caller is not the administrator, or the write fails.
pub(crate) async fn create_invite_code(
    _: Admin,
    State(accounts): State<Arc<Manager>>,
    Input(input): Input<One>,
) -> xrpc::Result<Json<Code>> {
    let account = input.for_account.as_deref().unwrap_or(ADMINISTRATOR);
    let mut codes = accounts.mint_invites(account, 1, input.use_count)?;
    Ok(Json(Code {
        code: codes
            .pop()
            .ok_or_else(|| xrpc::Error::internal("asked for one invite code and was given none"))?,
    }))
}

/// `com.atproto.server.createInviteCodes`
///
/// # Errors
///
/// If the caller is not the administrator, or the write fails.
pub(crate) async fn create_invite_codes(
    _: Admin,
    State(accounts): State<Arc<Manager>>,
    Input(input): Input<Many>,
) -> xrpc::Result<Json<Codes>> {
    let for_accounts = input
        .for_accounts
        .unwrap_or_else(|| vec![ADMINISTRATOR.to_owned()]);

    let mut codes = Vec::with_capacity(for_accounts.len());
    for account in for_accounts {
        let minted = accounts.mint_invites(&account, input.code_count, input.use_count)?;
        codes.push(Held {
            account,
            codes: minted,
        });
    }
    Ok(Json(Codes { codes }))
}
