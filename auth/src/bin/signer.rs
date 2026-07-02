//! The signer CLI: manage the issuer key and pairing registry, and mint
//! credentials. Pairing is the root of trust and is done here (CLI, out of
//! band) — there is no network-reachable enrollment endpoint by design.
//!
//! Usage:
//!   signer -secrets <path> pubkey
//!   signer -secrets <path> enroll --pubkey <hex> --rights a,b,c --lanes x,y [--note ...]
//!   signer -secrets <path> mint --id <pubkey-hex>
//!   signer -secrets <path> list

use dispatch_auth::signer::{Pairing, Signer};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut secrets = "secrets.json".to_string();
    let mut rest: Vec<String> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "-secrets" && i + 1 < args.len() {
            secrets = args[i + 1].clone();
            i += 2;
        } else {
            rest.push(args[i].clone());
            i += 1;
        }
    }
    if rest.is_empty() {
        usage();
    }

    let cmd = rest[0].as_str();
    match cmd {
        "pubkey" => {
            let s = Signer::open(&secrets).expect("open signer");
            println!("{}", s.public_key_b64());
        }
        "list" => {
            let s = Signer::open(&secrets).expect("open signer");
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
            let mut s = Signer::open(&secrets).expect("open signer");
            let cred = s
                .enroll(Pairing {
                    pubkey_hex: pubkey,
                    rights,
                    lanes,
                    note,
                })
                .expect("enroll");
            println!("{cred}");
        }
        "mint" => {
            let id = flag(&rest, "--id").expect("--id required");
            let s = Signer::open(&secrets).expect("open signer");
            let cred = s.mint_for(&id).expect("mint");
            println!("{cred}");
        }
        _ => usage(),
    }
}

fn usage() -> ! {
    eprintln!("usage: signer -secrets <path> [pubkey|list|enroll|mint] ...");
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
