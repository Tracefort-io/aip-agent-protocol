use std::time::{Duration, SystemTime};

use crate::canonical::{int_fact, time_check, tool_check};

/// Simple policy profile -- generates canonical Datalog from user-specified values.
/// Budget is in integer cents (Biscuit Datalog has no float type).
pub struct SimplePolicy {
    pub tools: Vec<String>,
    pub budget_cents: Option<i64>,
    pub max_depth: Option<u32>,
    pub ttl_seconds: Option<u64>,
}

/// Policy profile enum for all supported profiles.
pub enum PolicyProfile {
    Simple(SimplePolicy),
    Standard(String),   // raw Datalog string
    Advanced(String),   // raw Datalog string
}

impl SimplePolicy {
    /// Generate canonical Datalog in the forms and order mandated by
    /// draft-prakash-aip-01 Section 3.4.1: `max_depth` and `budget_ceiling` as
    /// facts, then the self-contained tool check, then the expiry check.
    ///
    /// Depth and budget are facts, not checks. Section 3.4.1 states that
    /// implementations MUST NOT emit a check statement over budget, because such
    /// a check binds to whatever budget facts are in scope at evaluation rather
    /// than to this block's ceiling. Both dimensions are verified structurally in
    /// step V4 of Section 4 instead. See [`crate::canonical`].
    pub fn to_datalog(&self) -> String {
        let mut out = String::new();

        if let Some(depth) = self.max_depth {
            out.push_str(&int_fact("max_depth", i64::from(depth)));
        }

        if let Some(cents) = self.budget_cents {
            out.push_str(&int_fact("budget_ceiling", cents));
        }

        if !self.tools.is_empty() {
            let refs: Vec<&str> = self.tools.iter().map(String::as_str).collect();
            out.push_str(&tool_check(&refs));
        }

        if let Some(ttl) = self.ttl_seconds {
            out.push_str(&time_check(SystemTime::now() + Duration::from_secs(ttl)));
        }

        out
    }
}

impl PolicyProfile {
    pub fn to_datalog(&self) -> String {
        match self {
            Self::Simple(p) => p.to_datalog(),
            Self::Standard(d) | Self::Advanced(d) => d.clone(),
        }
    }
}
