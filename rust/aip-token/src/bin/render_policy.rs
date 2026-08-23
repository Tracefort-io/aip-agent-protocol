//! Render a Simple-profile policy as canonical Datalog and print it to stdout.
//!
//! Exists so the cross-language conformance suite can compare the Rust and
//! Python renderings of the canonical encoding byte for byte. The two
//! implementations of Section 3.4.1 are independent, and silent drift between
//! them produces tokens neither side can verify.
//!
//! Usage:
//!   render_policy --tools a,b --budget-cents 100 --max-depth 3
//!
//! `--ttl-seconds` is deliberately not supported: expiry is wall-clock
//! dependent and cannot be compared across two processes.

use aip_token::policy::SimplePolicy;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut tools: Vec<String> = Vec::new();
    let mut budget_cents: Option<i64> = None;
    let mut max_depth: Option<u32> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--tools" => {
                i += 1;
                if i < args.len() && !args[i].is_empty() {
                    tools = args[i].split(',').map(|s| s.to_string()).collect();
                }
            }
            "--budget-cents" => {
                i += 1;
                budget_cents = args.get(i).and_then(|v| v.parse().ok());
            }
            "--max-depth" => {
                i += 1;
                max_depth = args.get(i).and_then(|v| v.parse().ok());
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let policy = SimplePolicy {
        tools,
        budget_cents,
        max_depth,
        ttl_seconds: None,
    };

    print!("{}", policy.to_datalog());
}
