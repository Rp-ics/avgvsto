use ring::rand::{SecureRandom, SystemRandom};
use std::fs::{self, File};
use std::io::{Seek, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::error::{CoreError, CoreResult};
use crate::SECURE_DELETE_PASSES;

/// Securely delete a file by overwriting with random data then zeros.
/// On HDDs this is effective. On SSDs/flash, wear-levelling may remap sectors,
/// so this provides best-effort protection.
pub fn secure_delete(path: &Path, cancel: Option<Arc<AtomicBool>>) -> CoreResult<()> {
    let size = fs::metadata(path)
        .map_err(|e| CoreError::SecureDelete(e.to_string()))?
        .len();

    if size == 0 {
        fs::remove_file(path).ok();
        return Ok(());
    }

    let mut file = File::options()
        .write(true)
        .read(false)
        .open(path)
        .map_err(|e| CoreError::SecureDelete(e.to_string()))?;

    let rng = SystemRandom::new();

    for pass in 0..SECURE_DELETE_PASSES {
        if let Some(ref cancel_flag) = cancel {
            if cancel_flag.load(Ordering::Relaxed) {
                return Err(CoreError::SecureDelete("operation cancelled".to_string()));
            }
        }

        file.seek(std::io::SeekFrom::Start(0))
            .map_err(|e| CoreError::SecureDelete(e.to_string()))?;

        let mut remaining = size;
        let chunk_size: u64 = 65536;

        while remaining > 0 {
            let chunk_len = remaining.min(chunk_size) as usize;
            let mut chunk = vec![0u8; chunk_len];
            rng.fill(&mut chunk)
                .map_err(|e| CoreError::SecureDelete(e.to_string()))?;
            file.write_all(&chunk)
                .map_err(|e| CoreError::SecureDelete(e.to_string()))?;
            remaining -= chunk_len as u64;
        }

        file.flush()
            .map_err(|e| CoreError::SecureDelete(e.to_string()))?;
        file.sync_all()
            .map_err(|e| CoreError::SecureDelete(e.to_string()))?;

        tracing::debug!("Secure delete pass {}/{} completed", pass + 1, SECURE_DELETE_PASSES);
    }

    // Final zero pass
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(|e| CoreError::SecureDelete(e.to_string()))?;
    let zero_chunk = vec![0u8; 65536];
    let mut remaining = size;
    while remaining > 0 {
        let write_len = remaining.min(65536) as usize;
        file.write_all(&zero_chunk[..write_len])
            .map_err(|e| CoreError::SecureDelete(e.to_string()))?;
        remaining -= write_len as u64;
    }
    file.flush()
        .map_err(|e| CoreError::SecureDelete(e.to_string()))?;
    file.sync_all()
        .map_err(|e| CoreError::SecureDelete(e.to_string()))?;

    drop(file);
    fs::remove_file(path)
        .map_err(|e| CoreError::SecureDelete(e.to_string()))?;

    tracing::debug!("File securely deleted: {:?}", path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_secure_delete_removes_file() {
        let dir = std::env::temp_dir().join(format!("avgvsto_test_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("test_file.bin");
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"test data for secure deletion").unwrap();
        drop(file);

        assert!(file_path.exists());
        secure_delete(&file_path, None).unwrap();
        assert!(!file_path.exists());

        fs::remove_dir_all(&dir).ok();
    }
}
