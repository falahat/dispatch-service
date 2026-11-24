//! The Datalog the PEP adds to the credentials it evaluates: its checks, its policy, and
//! its rights query. Each is biscuit's own Datalog text, parsed once. A request binds its
//! values with `set`, so a caller's string is never spliced into a rule. [`check`] parses
//! and binds every rule at boot, so a broken one stops the PEP before it serves instead of
//! failing every request.

use crate::error::{AuthError, Result};
use biscuit_auth::builder::{Check, Policy, Rule};
use biscuit_auth::error::Token as BiscuitError;
use std::sync::LazyLock;

/// A rule parsed once, or why it did not parse (said only at boot, never to a client).
type Parsed<T> = LazyLock<std::result::Result<T, String>>;

static PUBKEY_BOUND: Parsed<Check> =
    LazyLock::new(|| parsed(Check::try_from("check if pubkey($p), presented_pubkey($p)")));
static LANE_GRANTED: Parsed<Check> =
    LazyLock::new(|| parsed(Check::try_from("check if lane({l})")));
static RIGHT_GRANTED: Parsed<Policy> =
    LazyLock::new(|| parsed(Policy::try_from("allow if right({o})")));
static LEASE_GETS: Parsed<Check> = LazyLock::new(|| {
    parsed(Check::try_from(
        "check if operation(\"cas_get\"), address($a), allowed_get($a)",
    ))
});
static EXPIRY: Parsed<Check> =
    LazyLock::new(|| parsed(Check::try_from("check if now($t), $t <= {exp}")));
static RIGHTS_QUERY: Parsed<Rule> =
    LazyLock::new(|| parsed(Rule::try_from("granted($r) <- right($r)")));

fn parsed<T>(rule: std::result::Result<T, BiscuitError>) -> std::result::Result<T, String> {
    rule.map_err(|e| e.to_string())
}

/// Parses every rule and binds each of its parameters as a request would, naming the first
/// rule that fails.
pub fn check() -> std::result::Result<(), String> {
    let rules: [(&str, Option<&String>, Result<()>); 6] = [
        (
            "pubkey binding",
            PUBKEY_BOUND.as_ref().err(),
            pubkey_bound().map(drop),
        ),
        (
            "lane grant",
            LANE_GRANTED.as_ref().err(),
            lane_granted("lane").map(drop),
        ),
        (
            "right grant",
            RIGHT_GRANTED.as_ref().err(),
            right_granted("right").map(drop),
        ),
        (
            "lease reads",
            LEASE_GETS.as_ref().err(),
            lease_gets().map(drop),
        ),
        ("lease expiry", EXPIRY.as_ref().err(), expiry(0).map(drop)),
        (
            "rights query",
            RIGHTS_QUERY.as_ref().err(),
            rights_query().map(drop),
        ),
    ];
    for (name, unparsed, ready) in rules {
        if let Some(e) = unparsed {
            return Err(format!("policy {name} does not parse: {e}"));
        }
        if ready.is_err() {
            return Err(format!("policy {name} leaves a parameter unbound"));
        }
    }
    Ok(())
}

/// The presented pubkey must be the one the credential binds.
pub(crate) fn pubkey_bound() -> Result<Check> {
    bound(cloned(&PUBKEY_BOUND)?)
}

/// The credential must grant `lane`.
pub(crate) fn lane_granted(lane: &str) -> Result<Check> {
    let mut check = cloned(&LANE_GRANTED)?;
    check.set("l", lane).map_err(internal)?;
    bound(check)
}

/// Allows the request when the credential grants `right`.
pub(crate) fn right_granted(right: &str) -> Result<Policy> {
    let mut policy = cloned(&RIGHT_GRANTED)?;
    policy.set("o", right).map_err(internal)?;
    bound(policy)
}

/// A lease token's `cas_get` must name an address its lease allows.
pub(crate) fn lease_gets() -> Result<Check> {
    bound(cloned(&LEASE_GETS)?)
}

/// A lease token expires with its lease, at `expire_ts_ms`.
pub(crate) fn expiry(expire_ts_ms: i64) -> Result<Check> {
    let mut check = cloned(&EXPIRY)?;
    check.set("exp", expire_ts_ms).map_err(internal)?;
    bound(check)
}

/// The rights an authority block grants.
pub(crate) fn rights_query() -> Result<Rule> {
    bound(cloned(&RIGHTS_QUERY)?)
}

fn cloned<T: Clone>(rule: &Parsed<T>) -> Result<T> {
    rule.as_ref().cloned().map_err(|_| AuthError::Internal)
}

/// A rule whose `{param}`s must all be bound before it is used.
trait Parameterized {
    fn validate_parameters(&self) -> std::result::Result<(), BiscuitError>;
}

impl Parameterized for Check {
    fn validate_parameters(&self) -> std::result::Result<(), BiscuitError> {
        Check::validate_parameters(self)
    }
}

impl Parameterized for Policy {
    fn validate_parameters(&self) -> std::result::Result<(), BiscuitError> {
        Policy::validate_parameters(self)
    }
}

impl Parameterized for Rule {
    fn validate_parameters(&self) -> std::result::Result<(), BiscuitError> {
        Rule::validate_parameters(self)
    }
}

/// `rule`, if every parameter in it is bound. biscuit checks this when a check or policy is
/// added, but its query panics on an unbound parameter instead, so it is checked here for all.
fn bound<T: Parameterized>(rule: T) -> Result<T> {
    rule.validate_parameters().map_err(internal)?;
    Ok(rule)
}

fn internal(_: BiscuitError) -> AuthError {
    AuthError::Internal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_parses_and_binds() {
        assert_eq!(check(), Ok(()));
    }

    #[test]
    fn a_rule_with_an_unbound_parameter_is_an_internal_error() {
        // biscuit's query_with_limits panics on this rule: "Remaining parameter l".
        let query = Rule::try_from("granted($r) <- right($r), lane({l})").unwrap();
        assert!(matches!(bound(query), Err(AuthError::Internal)));
        let check = Check::try_from("check if lane({l})").unwrap();
        assert!(matches!(bound(check), Err(AuthError::Internal)));
    }
}
