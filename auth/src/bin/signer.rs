//! The signer CLI: manage the issuer key and pairing registry, and mint
//! credentials. Pairing is the root of trust and is done here (CLI, out of
//! band) — there is no network-reachable enrollment endpoint by design.
//!
//! Usage:
//!   signer -secrets <path> [-pairings <path>] pubkey
//!   signer -secrets <path> [-pairings <path>] enroll --pubkey <hex> --rights a,b,c --lanes x,y [--note ...]
//!   signer -secrets <path> [-pairings <path>] mint --id <pubkey-hex>
//!   signer -secrets <path> [-pairings <path>] revoke --pubkey <hex> [--deny-list <path>]
//!   signer -secrets <path> [-pairings <path>] list
//!
//! `revoke` appends the enrolled identity's recorded authority revocation id to
//! the PEP's deny-list (default `pep-revocations.json`, matching `PEP_REVOCATION_DB`);
//! the PEP live-reloads it, denying the credential and every lease attenuated from it.
//!
//! `-secrets` may point at the deployed easy-podcast SecretStore (read-only; the
//! issuer key is preserved) or this signer's own key file. `-pairings` is the
//! plane's own registry (default: plane-pairings.json next to the key file).

use dispatch_auth::signer::{Pairing, Signer};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut secrets = "secrets.json".to_string();
    let mut pairings: Option<String> = None;
    let mut rest: Vec<String> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "-secrets" && i + 1 < args.len() {
            secrets = args[i + 1].clone();
            i += 2;
        } else if args[i] == "-pairings" && i + 1 < args.len() {
            pairings = Some(args[i + 1].clone());
            i += 2;
        } else {
            rest.push(args[i].clone());
            i += 1;
        }
    }
    if rest.is_empty() {
        usage();
    }
    let open = |secrets: &str| match &pairings {
        Some(p) => Signer::open_with(secrets, p),
        None => Signer::open(secrets),
    };

    let cmd = rest[0].as_str();
    match cmd {
        "pubkey" => {
            let s = open(&secrets).expect("open signer");
            println!("{}", s.public_key_b64());
        }
        "list" => {
            let s = open(&secrets).expect("open signer");
            for (id, p) in s.pairings() {
                println!(
                    "{id}\trights={}\tlanes={}",
                    p.rights.join(","),
                    p.lanes.join(",")
                );
            }
        }
        "enroll" => {
            let pubkey = flag(&rest, "--pubkey").expect("--pubkey required");
            let rights = flag(&rest, "--rights").map(csv).unwrap_or_default();
            let lanes = flag(&rest, "--lanes").map(csv).unwrap_or_default();
            let note = flag(&rest, "--note");
            let mut s = open(&secrets).expect("open signer");
            let cred = s
                .enroll(Pairing {
                    pubkey_hex: pubkey,
                    rights,
                    lanes,
                    note,
                    revocation_id: String::new(),
                })
                .expect("enroll");
            println!("{cred}");
        }
        "mint" => {
            let id = flag(&rest, "--id").expect("--id required");
            let s = open(&secrets).expect("open signer");
            let cred = s.mint_for(&id).expect("mint");
            println!("{cred}");
        }
        "revoke" => {
            // Root-of-trust CLI: append an enrolled identity's recorded revocation
            // id to the PEP's deny-list. The PEP live-reloads the file, so the next
            // request bearing that credential (or any lease attenuated from it) is
            // denied. Default path matches the PEP's PEP_REVOCATION_DB default.
            let pubkey = flag(&rest, "--pubkey").expect("--pubkey required");
            let deny_list =
                flag(&rest, "--deny-list").unwrap_or_else(|| "pep-revocations.json".to_string());
            let mut s = open(&secrets).expect("open signer");
            s.revoke(&pubkey, &deny_list, now_ms()).expect("revoke");
            eprintln!("revoked {pubkey} -> {deny_list}");
        }
        _ => usage(),
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn usage() -> ! {
    eprintln!("usage: signer -secrets <path> [pubkey|list|enroll|mint|revoke] ...");
    eprintln!("  revoke --pubkey <hex> [--deny-list <path>]   append the pairing's");
    eprintln!("        revocation id to the PEP deny-list (default pep-revocations.json)");
    std::process::exit(2);
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn csv(s: String) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}
