// Every code block in README.md, compiled but never run.
//
// The README is the API contract customers actually read, so a rename or a
// signature change that invalidates it should fail the build rather than reach
// a reader. Mirror any README edit here.
#![allow(unused, path_statements, clippy::no_effect)]

use std::time::Duration;
use vpndetection::{BatchOptions, Client, ErrorKind, Format};

async fn snippets() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new()?;
    let result = client.lookup("45.83.91.1").await?;
    println!("{}", result.is_vpn);

    let client = Client::builder().api_key(std::env::var("VPNDETECTION_API_KEY")?).build()?;
    let result = client.lookup("45.83.91.1").await?;
    println!("{}", result.is_vpn);
    println!("{:?}", result.is_hosting);
    if let Some(vpn) = result.vpn.as_deref() {
        println!("{:?}", vpn.provider);
    }

    let key = std::env::var("VPNDETECTION_API_KEY")?;
    let client = Client::builder().api_key(key).concurrency(32).retries(4).build()?;

    let results =
        client.lookup_batch(["45.83.91.1", "8.8.8.8", "1.1.1.1"], BatchOptions::new()).await;
    for (ip, result) in &results {
        match result {
            Ok(result) => println!("{ip}: {}", result.is_vpn),
            Err(err) => eprintln!("{ip}: {err}"),
        }
    }
    let many_ips = vec!["1.1.1.1".to_owned()];
    let results =
        client.lookup_batch(many_ips, BatchOptions::new().concurrency(32).retries(4)).await;

    let client = Client::new()?;
    let result = client.lookup("45.83.91.1").await?;
    println!("{}", result.is_vpn);
    let result2 = client.lookup("45.83.91.1").await?;
    println!("{}", result2.is_vpn);

    let client = Client::builder().cache(50_000, Duration::from_secs(6 * 60 * 60)).build()?;
    let client_no_cache = Client::builder().no_cache().build()?;

    let result = client.lookup("192.168.1.1").await?;
    result.is_bogon;
    result.is_vpn;

    client.is_bogon("10.0.0.1");
    client.is_bogon("8.8.8.8");
    vpndetection::is_bogon("10.0.0.1");

    match client.lookup("1.1.1.1").await {
        Ok(result) => println!("{}", result.is_vpn),
        Err(err) => println!("{} {}", err.kind(), err.retryable()),
    }
    let _ = [
        ErrorKind::BadRequest,
        ErrorKind::Unauthorized,
        ErrorKind::Forbidden,
        ErrorKind::RateLimited,
        ErrorKind::QuotaExceeded,
        ErrorKind::ServerError,
        ErrorKind::Network,
        ErrorKind::Io,
    ];

    let families = client.database().list().await?;
    let url = client.database().download_url("vpn_ip_extended_v1", Format::Mmdb).await?;
    let raw = client.database().download_bytes("cdn_ip_v1", Format::Csvgz).await?;
    let written =
        client.database().download("vpn_ip_extended_v1", Format::Mmdb, "./vpn_ip.mmdb").await?;

    result.is_hosting.unwrap_or(false);
    result.is_hosting.is_none();
    Ok(())
}

fn blocking_snippet() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Runtime::new()?;
    let client = Client::new()?;
    let result = runtime.block_on(client.lookup("45.83.91.1"))?;
    Ok(())
}
