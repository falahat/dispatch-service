//! The dispatch plane's single auth engine (Rust): Biscuit + PoP verification
//! and the credential signer. It is the only place any credential is verified;
//! backends receive pre-authenticated requests over loopback and hold no auth
//! crypto. See docs/TRUST_PLANE.md.

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
