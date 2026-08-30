//! File and viewer lifecycle for the non-terminal `herdr pair` QR outputs.

use std::io::Write as _;
use std::path::{Path, PathBuf};

pub(super) struct PairingQrFile {
    path: PathBuf,
    remove_on_drop: bool,
}

impl PairingQrFile {
    pub(super) fn create(svg: &str, requested: Option<&Path>) -> std::io::Result<Self> {
        if let Some(path) = requested {
            return Self::create_at(svg, absolute_path(path)?, false);
        }
        for _ in 0..32 {
            let path = temporary_qr_path()?;
            match Self::create_at(svg, path, true) {
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                result => return result,
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not choose an unused temporary QR path",
        ))
    }

    fn create_at(svg: &str, path: PathBuf, remove_on_drop: bool) -> std::io::Result<Self> {
        let mut file = crate::platform::create_private_file(&path)?;
        if let Err(err) = file.write_all(svg.as_bytes()).and_then(|()| file.flush()) {
            let _ = std::fs::remove_file(&path);
            return Err(err);
        }
        Ok(Self {
            path,
            remove_on_drop,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PairingQrFile {
    fn drop(&mut self) {
        if self.remove_on_drop {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn absolute_path(path: &Path) -> std::io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn temporary_qr_path() -> std::io::Result<PathBuf> {
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|err| std::io::Error::other(format!("no OS randomness for QR file: {err}")))?;
    let mut suffix = String::with_capacity(random.len() * 2);
    use std::fmt::Write as _;
    for byte in random {
        let _ = write!(suffix, "{byte:02x}");
    }
    Ok(std::env::temp_dir().join(format!("herdr-pair-{suffix}.svg")))
}

pub(super) fn open_qr_with(
    path: &Path,
    open: impl FnOnce(&Path) -> std::io::Result<Option<std::process::Child>>,
) -> Option<String> {
    open(path)
        .err()
        .map(|err| format!("could not open the QR image automatically: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_path(label: &str) -> PathBuf {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).expect("test randomness");
        let suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        std::env::temp_dir().join(format!("herdr-pair-test-{label}-{suffix}.svg"))
    }

    #[test]
    fn an_explicit_qr_file_is_private_and_is_not_removed() {
        let path = test_path("explicit");
        let artifact = PairingQrFile::create("<svg/>\n", Some(&path)).expect("create QR");
        assert_eq!(artifact.path(), path);
        assert_eq!(std::fs::read_to_string(&path).expect("read QR"), "<svg/>\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path)
                    .expect("QR metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        drop(artifact);
        assert!(path.exists(), "an explicitly requested file must persist");
        std::fs::remove_file(path).expect("remove test QR");
    }

    #[test]
    fn an_existing_qr_file_is_never_overwritten() {
        let path = test_path("existing");
        std::fs::write(&path, "keep me").expect("seed existing file");
        let err = PairingQrFile::create("replacement", Some(&path))
            .err()
            .expect("must refuse overwrite");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read_to_string(&path).expect("read original"),
            "keep me"
        );
        std::fs::remove_file(path).expect("remove test file");
    }

    #[test]
    fn a_temporary_qr_file_is_removed_on_drop() {
        let artifact = PairingQrFile::create("<svg/>\n", None).expect("create temp QR");
        let path = artifact.path().to_path_buf();
        assert!(path.exists());
        drop(artifact);
        assert!(!path.exists());
    }

    #[test]
    fn opener_failure_is_a_warning_with_the_file_left_usable() {
        let path = Path::new("/tmp/herdr-pair-example.svg");
        let warning = open_qr_with(path, |_path| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no viewer",
            ))
        })
        .expect("warning");
        assert!(warning.contains("no viewer"));
        assert!(warning.contains("could not open"));
    }
}
