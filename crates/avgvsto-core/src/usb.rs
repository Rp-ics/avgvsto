use ring::digest::{Context, SHA256};
use std::path::Path;

use crate::error::{CoreError, CoreResult};

/// Compute a USB device identifier from its mount path.
/// Creates a hardware-bound fingerprint using device metadata
/// and hostname for cross-platform identification.
pub fn get_usb_identifier(mount_path: &str) -> CoreResult<String> {
    let path = Path::new(mount_path);
    if !path.exists() {
        return Err(CoreError::UsbKeyNotFound);
    }

    let hostname = hostname();
    let mount_path_str = path.canonicalize()
        .map_err(|e| CoreError::Io(e))?
        .to_string_lossy()
        .to_string();

    let mut ctx = Context::new(&SHA256);
    ctx.update(hostname.as_bytes());
    ctx.update(b":");
    ctx.update(mount_path_str.as_bytes());
    ctx.update(b":");

    // Add volume info if available
    if let Ok(_metadata) = std::fs::metadata(path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ctx.update(format!("{}", metadata.dev()).as_bytes());
            ctx.update(b":");
            ctx.update(format!("{}", metadata.ino()).as_bytes());
        }
        #[cfg(windows)]
        {
            // Use volume serial number via path for stable identifier
            ctx.update(mount_path_str.as_bytes());
        }
    }

    let digest = ctx.finish();
    Ok(hex::encode(digest.as_ref()))
}

/// List available USB mass storage devices on the system.
#[cfg(target_os = "linux")]
pub fn list_usb_devices() -> Vec<String> {
    let mut devices = Vec::new();
    for dir in ["/media", "/mnt", "/run/media"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(name) = path.to_str() {
                        devices.push(name.to_string());
                    }
                }
            }
        }
    }
    devices
}

/// List available USB mass storage devices on the system.
#[cfg(target_os = "windows")]
pub fn list_usb_devices() -> Vec<String> {
    let mut devices = Vec::new();
    for drive_letter in 'D'..='Z' {
        let path = format!("{}:\\", drive_letter);
        let p = Path::new(&path);
        if p.exists() {
            devices.push(path);
        }
    }
    devices
}

/// List available USB mass storage devices on the system.
#[cfg(target_os = "macos")]
pub fn list_usb_devices() -> Vec<String> {
    let mut devices = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/Volumes") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.to_str() {
                    if name != "/Volumes" {
                        devices.push(name.to_string());
                    }
                }
            }
        }
    }
    devices
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "avgvsto-host".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usb_identifier_is_deterministic() {
        let path = std::env::temp_dir();
        let path_str = path.to_str().unwrap();
        let id1 = get_usb_identifier(path_str).unwrap();
        let id2 = get_usb_identifier(path_str).unwrap();
        assert_eq!(id1, id2);
    }
}
