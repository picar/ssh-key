use std::fmt;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::{fs, io};

use sshkey::private::{KeypairData, RsaKeypair};
use sshkey::{Algorithm, EcdsaCurve, LineEnding, PrivateKey};

#[derive(Clone, clap::ValueEnum)]
pub enum KeyType {
    Ed25519,
    Rsa,
    #[value(name = "ecdsa-p256")]
    EcdsaP256,
    #[value(name = "ecdsa-p384")]
    EcdsaP384,
    #[value(name = "ecdsa-p521")]
    EcdsaP521,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyType::Ed25519 => write!(f, "ed25519"),
            KeyType::Rsa => write!(f, "rsa"),
            KeyType::EcdsaP256 => write!(f, "ecdsa_p256"),
            KeyType::EcdsaP384 => write!(f, "ecdsa_p384"),
            KeyType::EcdsaP521 => write!(f, "ecdsa_p521"),
        }
    }
}

/// Generate a key pair and write it to disk.
///
/// The private key is written to `output` (mode 0600) and the public key to
/// `output.pub`. If `output` is `None` the default path `~/.ssh/id_<type>` is
/// used. Returns `(private_key_path, public_key_path)` on success.
pub fn generate(
    key_type: KeyType,
    output: Option<&str>,
    comment: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let private_path = output
        .map(|p| p.to_owned())
        .unwrap_or_else(|| default_key_path(&key_type.to_string()));
    let public_path = format!("{}.pub", private_path);

    if Path::new(&private_path).exists() {
        return Err(format!("{} already exists", private_path).into());
    }

    // Ensure the parent directory exists.
    if let Some(parent) = Path::new(&private_path).parent() {
        fs::create_dir_all(parent)?;
    }

    let mut rng = rand::rngs::OsRng;

    let private_key = match key_type {
        KeyType::Rsa => {
            let keypair = RsaKeypair::random(&mut rng, 4096)?;
            PrivateKey::new(KeypairData::Rsa(keypair), comment)?
        }
        KeyType::Ed25519 => {
            let mut key = PrivateKey::random(&mut rng, Algorithm::Ed25519)?;
            key.set_comment(comment);
            key
        }
        KeyType::EcdsaP256 => {
            let mut key = PrivateKey::random(&mut rng, Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 })?;
            key.set_comment(comment);
            key
        }
        KeyType::EcdsaP384 => {
            let mut key = PrivateKey::random(&mut rng, Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 })?;
            key.set_comment(comment);
            key
        }
        KeyType::EcdsaP521 => {
            let mut key = PrivateKey::random(&mut rng, Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 })?;
            key.set_comment(comment);
            key
        }
    };

    // Write private key with restrictive permissions (0600).
    let private_pem = private_key.to_openssh(LineEnding::LF)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&private_path)
        .map_err(|e| io_error_with_path(e, &private_path))?;
    file.write_all(private_pem.as_bytes())?;

    // Write public key (default mode 0644).
    let public_str = private_key.public_key().to_openssh()?;
    fs::write(&public_path, public_str.as_bytes())
        .map_err(|e| io_error_with_path(e, &public_path))?;

    Ok((private_path, public_path))
}

fn default_key_path(type_name: &str) -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
    format!("{}/.ssh/id_{}", home, type_name)
}

fn io_error_with_path(e: io::Error, path: &str) -> Box<dyn std::error::Error> {
    format!("{}: {}", path, e).into()
}
