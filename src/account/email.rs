//! Whether an address could be delivered to, which is as much as anything can
//! tell before sending to it.

/// The longest each half may be, from the SMTP limits on a path.
const LOCAL: usize = 64;
const DOMAIN: usize = 255;

/// Characters an address may carry outside the letters and digits. The set is
/// the one a local part is allowed by RFC 5322 without being quoted.
const PUNCTUATION: &str = "!#$%&'*+-/=?^_`{|}~.";

/// Whether an address is shaped like one that could be delivered to.
///
/// Nothing here says the address exists. Confirming it is the only thing that
/// does, which is what the confirmation email is for.
#[must_use]
pub fn plausible(address: &str) -> bool {
    // todo: the reference also refuses addresses at known disposable domains.
    let Some((local, domain)) = address.split_once('@') else {
        return false;
    };
    if domain.contains('@') {
        return false;
    }
    local_part(local) && domain_part(domain)
}

fn local_part(local: &str) -> bool {
    !local.is_empty()
        && local.len() <= LOCAL
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || PUNCTUATION.contains(c))
}

fn domain_part(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > DOMAIN || !domain.contains('.') {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}
