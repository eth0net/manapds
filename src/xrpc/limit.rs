//! Rate limits: the budgets a caller spends and what is left of them.
//!
//! A budget is a fixed window, counted in memory. Points already spent are not
//! given back when a request is refused, so a client hammering a spent budget
//! waits out the window rather than pushing it along.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::config::{Config, Secret};

use super::{Error, Status};

/// What every caller gets, keyed by address.
const GLOBAL_POINTS: u32 = 3000;

/// The window that budget refills on.
const GLOBAL_WINDOW: Duration = Duration::from_mins(5);

/// A sync path large enough that one call would eat a shared budget, so it
/// is left to the budget its own method holds.
// todo(per-method budgets): upstream pairs this exemption with 6000 points per
// five minutes on the method itself. Serving getRepo before that exists would
// leave the most expensive read here the only one nothing counts.
const UNBUDGETED: &str = "/xrpc/com.atproto.sync.getRepo";

/// The header a caller with the bypass key sends it in.
const BYPASS: HeaderName = HeaderName::from_static("x-ratelimit-bypass");

/// The header a proxy in front of this server names the caller in.
const FORWARDED: HeaderName = HeaderName::from_static("x-forwarded-for");

/// One budget, and how much of it each key has spent.
#[derive(Debug)]
pub struct Limiter {
    points: u32,
    window: Duration,
    spent: Mutex<Counts>,
}

/// What every key has spent, and when expired keys were last dropped.
#[derive(Debug)]
struct Counts {
    windows: HashMap<String, Window>,
    swept: Instant,
}

#[derive(Debug)]
struct Window {
    points: u32,
    until: Instant,
}

/// What a budget looked like after a request was counted against it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reading {
    /// The whole budget.
    pub limit: u32,
    /// How long it takes to refill.
    pub window: Duration,
    /// What this key has spent of it.
    pub spent: u32,
    /// What is left, which is zero once the budget is gone.
    pub remaining: u32,
    /// How long until it refills.
    pub resets_in: Duration,
    /// Whether this request went past it.
    pub exceeded: bool,
}

impl Limiter {
    /// A budget of `points`, refilling every `window`.
    #[must_use]
    pub fn new(points: u32, window: Duration) -> Self {
        Self {
            points,
            window,
            spent: Mutex::new(Counts {
                windows: HashMap::new(),
                swept: Instant::now(),
            }),
        }
    }

    /// Counts `points` against a key, whether or not the budget covers them.
    ///
    /// # Panics
    ///
    /// If another thread panicked while holding the counts.
    pub fn consume(&self, key: &str, points: u32) -> Reading {
        let now = Instant::now();
        let mut counts = self.spent.lock().expect("the counts are not poisoned");
        // A key outlives its window by at most one more, so sweeping that often
        // bounds the map without walking it on every request.
        if now.duration_since(counts.swept) >= self.window {
            counts.windows.retain(|_, window| window.until > now);
            counts.swept = now;
        }

        let window = counts
            .windows
            .entry(key.to_owned())
            .and_modify(|window| {
                if window.until <= now {
                    *window = Window {
                        points: 0,
                        until: now + self.window,
                    };
                }
            })
            .or_insert_with(|| Window {
                points: 0,
                until: now + self.window,
            });
        window.points = window.points.saturating_add(points);

        Reading {
            limit: self.points,
            window: self.window,
            spent: window.points,
            remaining: self.points.saturating_sub(window.points),
            resets_in: window.until - now,
            exceeded: window.points > self.points,
        }
    }
}

impl Reading {
    /// Tells the caller what it has left. The names are the draft standard's;
    /// the reset is a unix timestamp, which is what the reference sends rather
    /// than the seconds-from-now the draft asks for.
    pub fn write(self, headers: &mut HeaderMap) {
        let mut set = |name: HeaderName, value: String| {
            if let Ok(value) = HeaderValue::from_str(&value) {
                headers.insert(name, value);
            }
        };
        set(
            HeaderName::from_static("ratelimit-limit"),
            self.limit.to_string(),
        );
        set(
            HeaderName::from_static("ratelimit-remaining"),
            self.remaining.to_string(),
        );
        set(
            HeaderName::from_static("ratelimit-reset"),
            (jiff::Timestamp::now().as_second() + self.resets_in.as_secs().cast_signed())
                .to_string(),
        );
        set(
            HeaderName::from_static("ratelimit-policy"),
            format!("{};w={}", self.limit, self.window.as_secs()),
        );
        if self.exceeded {
            set(
                HeaderName::from_static("retry-after"),
                self.resets_in.as_secs().saturating_add(1).to_string(),
            );
        }
    }
}

/// The budgets this server holds every caller to.
#[derive(Debug)]
pub struct Limits {
    global: Limiter,
    bypass_key: Option<Secret>,
    bypass_ips: Vec<IpAddr>,
}

impl Limits {
    /// The budgets a configuration asks for, or `None` where it turns them off.
    ///
    /// Off is the default, as it is for the reference: a server behind nothing
    /// is the one that needs them, and a server behind something else is
    /// usually already counted there.
    #[must_use]
    pub fn new(config: &Config) -> Option<Self> {
        config.rate_limits.then(|| Self {
            global: Limiter::new(GLOBAL_POINTS, GLOBAL_WINDOW),
            bypass_key: config.rate_limit_bypass_key.clone(),
            bypass_ips: config.rate_limit_bypass_ips.clone(),
        })
    }

    fn bypassed(&self, caller: IpAddr, headers: &HeaderMap) -> bool {
        if self.bypass_ips.contains(&caller) {
            return true;
        }
        match (&self.bypass_key, headers.get(BYPASS)) {
            (Some(key), Some(offered)) => offered.as_bytes() == key.reveal().as_bytes(),
            _ => false,
        }
    }
}

/// Counts a request against the global budget before anything else looks at it.
pub async fn global(
    State(limits): State<Arc<Limits>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if !path.starts_with("/xrpc/") || path == UNBUDGETED {
        return next.run(request).await;
    }

    let caller = caller(peer.ip(), request.headers());
    if limits.bypassed(caller, request.headers()) {
        return next.run(request).await;
    }

    let reading = limits.global.consume(&budget(caller), 1);
    let mut response = if reading.exceeded {
        Error::new(Status::RateLimitExceeded).into_response()
    } else {
        next.run(request).await
    };
    reading.write(response.headers_mut());
    response
}

/// Who to count a request against.
///
/// `X-Forwarded-For` is read only past addresses that could not have reached
/// this server from outside, so a caller cannot name someone else by sending
/// the header itself.
#[must_use]
pub fn caller(peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    let peer = canonical(peer);
    if !internal(peer) {
        return peer;
    }
    headers
        .get_all(FORWARDED)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|part| part.trim().parse().ok())
        .map(canonical)
        .rfind(|address| !internal(*address))
        .unwrap_or(peer)
}

/// Which budget a caller spends from.
///
/// An IPv6 caller is counted with its `/64`, since one line holds the whole
/// range and can move through it for free.
#[must_use]
pub fn budget(caller: IpAddr) -> String {
    match caller {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => {
            let mut octets = address.octets();
            octets[8..].fill(0);
            format!("{}/64", Ipv6Addr::from(octets))
        }
    }
}

/// The one spelling of an address, so that a caller arriving as `::ffff:1.2.3.4`
/// and the same caller arriving as `1.2.3.4` are held to one budget.
fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address @ IpAddr::V4(_) => address,
    }
}

/// An address no packet from the internet carries as its source, which is what
/// makes a proxy claiming to speak for someone else worth believing.
fn internal(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_unspecified()
                // Carrier-grade NAT, which is what several hosting front-ends
                // put in front of a server.
                || address.octets()[0] == 100 && address.octets()[1] & 0xc0 == 64
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.is_unspecified()
                || unique_local(address)
                || link_local(address)
        }
    }
}

fn unique_local(address: Ipv6Addr) -> bool {
    address.octets()[0] & 0xfe == 0xfc
}

fn link_local(address: Ipv6Addr) -> bool {
    address.octets()[0] == 0xfe && address.octets()[1] & 0xc0 == 0x80
}
