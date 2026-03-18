use super::*;
use crate::error::ProxyError;
use crate::stats::Stats;
use crate::stream::BufferPool;
use std::sync::Arc;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, Instant, timeout};

// ------------------------------------------------------------------
// Priority 3: Async Relay HOL Blocking Prevention (OWASP ASVS 5.1.5)
// ------------------------------------------------------------------

#[tokio::test]
async fn relay_hol_blocking_prevention_regression() {
    let stats = Arc::new(Stats::new());
    let user = "hol-user";
    
    let (client_peer, relay_client) = duplex(65536);
    let (relay_server, server_peer) = duplex(65536);

    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);
    let (mut cp_reader, mut cp_writer) = tokio::io::split(client_peer);
    let (mut sp_reader, mut sp_writer) = tokio::io::split(server_peer);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        8192,
        8192,
        user,
        Arc::clone(&stats),
        None,
        Arc::new(BufferPool::new()),
    ));

    let payload_size = 1024 * 10;
    let s2c_payload = vec![0x41; payload_size];
    let c2s_payload = vec![0x42; payload_size];

    let s2c_handle = tokio::spawn(async move {
        sp_writer.write_all(&s2c_payload).await.unwrap();
        
        let mut total_read = 0;
        let mut buf = [0u8; 10];
        while total_read < payload_size {
            let n = cp_reader.read(&mut buf).await.unwrap();
            total_read += n;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    let start = Instant::now();
    cp_writer.write_all(&c2s_payload).await.unwrap();
    
    let mut server_buf = vec![0u8; payload_size];
    sp_reader.read_exact(&mut server_buf).await.unwrap();
    let elapsed = start.elapsed();

    assert!(elapsed < Duration::from_millis(1000), "C->S must not be blocked by slow S->C (HOL blocking): {:?}", elapsed);
    assert_eq!(server_buf, c2s_payload);

    s2c_handle.abort();
    relay_task.abort();
}

// ------------------------------------------------------------------
// Priority 3: Data Quota Mid-Session Cutoff (OWASP ASVS 5.1.6)
// ------------------------------------------------------------------

#[tokio::test]
async fn relay_quota_mid_session_cutoff() {
    let stats = Arc::new(Stats::new());
    let user = "quota-mid-user";
    let quota = 5000;
    
    let (client_peer, relay_client) = duplex(8192);
    let (relay_server, server_peer) = duplex(8192);

    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);
    let (mut _cp_reader, mut cp_writer) = tokio::io::split(client_peer);
    let (mut sp_reader, _sp_writer) = tokio::io::split(server_peer);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        1024,
        1024,
        user,
        Arc::clone(&stats),
        Some(quota),
        Arc::new(BufferPool::new()),
    ));

    // Send 4000 bytes (Ok)
    let buf1 = vec![0x42; 4000];
    cp_writer.write_all(&buf1).await.unwrap();
    let mut server_recv = vec![0u8; 4000];
    sp_reader.read_exact(&mut server_recv).await.unwrap();

    // Send another 2000 bytes (Total 6000 > 5000)
    let buf2 = vec![0x42; 2000];
    let _ = cp_writer.write_all(&buf2).await;
    
    let relay_res = timeout(Duration::from_secs(1), relay_task).await.unwrap();
    
    match relay_res {
        Ok(Err(ProxyError::DataQuotaExceeded { .. })) => {
            // Expected
        }
        other => panic!("Expected DataQuotaExceeded error, got: {:?}", other),
    }

    let mut small_buf = [0u8; 1];
    let n = sp_reader.read(&mut small_buf).await.unwrap();
    assert_eq!(n, 0, "Server must see EOF after quota reached");
}
