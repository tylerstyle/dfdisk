use crate::models::info_report::HashResults;
use digest::Digest;
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;
use tokio::sync::mpsc;

#[allow(dead_code)]
#[derive(Debug, Clone)]
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
            let mut file = File::open(&path_buf)
                .map_err(|e| format!("Failed to open {}: {}", path_buf.display(), e))?;

            let mut total_bytes = file.metadata().map(|m| m.len()).unwrap_or(0);
            if total_bytes == 0 {
                // For Linux block devices, metadata().len() returns 0.
                // Seek to the end of the block device to determine true capacity.
                if let Ok(end_pos) = file.seek(SeekFrom::End(0)) {
                    total_bytes = end_pos;
                    let _ = file.seek(SeekFrom::Start(0));
                }
            }

            let mut reader = BufReader::with_capacity(2 * 1024 * 1024, file); // 2 MB buffer

            let mut md5_hasher = if calc_md5 { Some(Md5::new()) } else { None };
            let mut sha1_hasher = if calc_sha1 { Some(Sha1::new()) } else { None };
            let mut sha256_hasher = if calc_sha256 {
                Some(Sha256::new())
            } else {
                None
            };

            let mut buffer = vec![0u8; 1024 * 1024]; // 1 MB chunk
            let mut bytes_hashed: u64 = 0;
            let start_time = Instant::now();
            let mut last_report = Instant::now();

            loop {
                let n = reader.read(&mut buffer).map_err(|e| {
                    format!("Read error while hashing {}: {}", path_buf.display(), e)
                })?;

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

            // Ensure final progress report reaches 100.0%
            if let Some(ref tx) = progress_tx {
                let elapsed_secs = start_time.elapsed().as_secs_f64();
                let speed_bps = if elapsed_secs > 0.0 {
                    bytes_hashed as f64 / elapsed_secs
                } else {
                    0.0
                };
                let final_total = if total_bytes == 0 {
                    bytes_hashed
                } else {
                    total_bytes
                };
                let _ = tx.blocking_send(HashProgress {
                    bytes_hashed,
                    total_bytes: final_total,
                    speed_bps,
                    percentage: 100.0,
                });
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[tokio::test]
    async fn test_hash_stream_known_vector() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("dfdisk_test_known_vector.txt");
        {
            let mut f = File::create(&test_file).unwrap();
            f.write_all(b"hello world").unwrap();
        }

        let (tx, mut rx) = mpsc::channel(10);
        let res = MultiHasher::hash_stream(&test_file, true, true, true, Some(tx))
            .await
            .expect("Hashing should succeed");

        assert_eq!(res.md5.as_deref(), Some("5eb63bbbe01eeed093cb22bb8f5acdc3"));
        assert_eq!(
            res.sha1.as_deref(),
            Some("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")
        );
        assert_eq!(
            res.sha256.as_deref(),
            Some("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        );

        // Verify final progress reaches 100%
        let mut last_progress = None;
        while let Some(prog) = rx.recv().await {
            last_progress = Some(prog);
        }
        let final_prog = last_progress.expect("Should have received progress");
        assert_eq!(final_prog.percentage, 100.0);
        assert_eq!(final_prog.bytes_hashed, 11);

        let _ = std::fs::remove_file(test_file);
    }

    #[tokio::test]
    async fn test_hash_stream_empty_file() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("dfdisk_test_empty.txt");
        {
            let _ = File::create(&test_file).unwrap();
        }

        let (tx, mut rx) = mpsc::channel(10);
        let res = MultiHasher::hash_stream(&test_file, true, false, false, Some(tx))
            .await
            .expect("Hashing should succeed");

        assert_eq!(res.md5.as_deref(), Some("d41d8cd98f00b204e9800998ecf8427e"));
        assert!(res.sha1.is_none());
        assert!(res.sha256.is_none());

        let mut last_progress = None;
        while let Some(prog) = rx.recv().await {
            last_progress = Some(prog);
        }
        let final_prog = last_progress.expect("Should have received progress");
        assert_eq!(final_prog.percentage, 100.0);
        assert_eq!(final_prog.bytes_hashed, 0);

        let _ = std::fs::remove_file(test_file);
    }
}
