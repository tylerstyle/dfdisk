use crate::models::info_report::HashResults;
use digest::Digest;
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::Instant;
use tokio::sync::mpsc;

#[allow(dead_code)]
pub struct HashProgress {
    pub bytes_hashed: u64,
    pub total_bytes: u64,
    pub speed_bps: f64,
    pub percentage: f64,
}

pub struct MultiHasher;

impl MultiHasher {
    /// Computes MD5, SHA-1, and SHA-256 simultaneously on a file or device
    pub async fn hash_stream(
        path: &Path,
        calc_md5: bool,
        calc_sha1: bool,
        calc_sha256: bool,
        progress_tx: Option<mpsc::Sender<HashProgress>>,
    ) -> Result<HashResults, String> {
        let path_buf = path.to_path_buf();

        tokio::task::spawn_blocking(move || {
            let file = File::open(&path_buf)
                .map_err(|e| format!("Failed to open {}: {}", path_buf.display(), e))?;

            let total_bytes = file.metadata().map(|m| m.len()).unwrap_or(0);
            let mut reader = BufReader::with_capacity(2 * 1024 * 1024, file); // 2 MB buffer

            let mut md5_hasher = if calc_md5 { Some(Md5::new()) } else { None };
            let mut sha1_hasher = if calc_sha1 { Some(Sha1::new()) } else { None };
            let mut sha256_hasher = if calc_sha256 { Some(Sha256::new()) } else { None };

            let mut buffer = vec![0u8; 1024 * 1024]; // 1 MB chunk
            let mut bytes_hashed: u64 = 0;
            let start_time = Instant::now();
            let mut last_report = Instant::now();

            loop {
                let n = reader
                    .read(&mut buffer)
                    .map_err(|e| format!("Read error while hashing {}: {}", path_buf.display(), e))?;

                if n == 0 {
                    break;
                }

                let chunk = &buffer[..n];
                if let Some(ref mut h) = md5_hasher {
                    h.update(chunk);
                }
                if let Some(ref mut h) = sha1_hasher {
                    h.update(chunk);
                }
                if let Some(ref mut h) = sha256_hasher {
                    h.update(chunk);
                }

                bytes_hashed += n as u64;

                if last_report.elapsed().as_millis() >= 100 {
                    if let Some(ref tx) = progress_tx {
                        let elapsed_secs = start_time.elapsed().as_secs_f64();
                        let speed_bps = if elapsed_secs > 0.0 {
                            bytes_hashed as f64 / elapsed_secs
                        } else {
                            0.0
                        };
                        let percentage = if total_bytes > 0 {
                            (bytes_hashed as f64 / total_bytes as f64) * 100.0
                        } else {
                            0.0
                        };

                        let _ = tx.blocking_send(HashProgress {
                            bytes_hashed,
                            total_bytes,
                            speed_bps,
                            percentage,
                        });
                    }
                    last_report = Instant::now();
                }
            }

            let md5_str = md5_hasher.map(|h| hex::encode(h.finalize()));
            let sha1_str = sha1_hasher.map(|h| hex::encode(h.finalize()));
            let sha256_str = sha256_hasher.map(|h| hex::encode(h.finalize()));

            Ok(HashResults {
                md5: md5_str,
                sha1: sha1_str,
                sha256: sha256_str,
            })
        })
        .await
        .map_err(|e| format!("Hasher task failed: {}", e))?
    }
}
