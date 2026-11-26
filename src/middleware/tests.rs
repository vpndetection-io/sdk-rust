// What an integration test cannot reach: how long, and how many, addresses
// remember their crawler agents. Waiting out the hour is not a test.

use std::time::Duration;

use super::{AGENTS_ADDRESSES, AGENTS_TTL, Agents};

#[test]
fn an_address_is_remembered_for_an_hour_from_its_first_agent() {
    assert_eq!(AGENTS_TTL, Duration::from_secs(60 * 60));
    assert_eq!(AGENTS_ADDRESSES, 10_000);
    let policy = Agents::new().seen.policy();
    assert_eq!(policy.time_to_live(), Some(AGENTS_TTL), "counted from the entry's write");
    assert_eq!(policy.time_to_idle(), None, "a read would extend the hour");
    assert_eq!(policy.max_capacity(), Some(AGENTS_ADDRESSES));
}
