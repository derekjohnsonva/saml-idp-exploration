use log::{debug, error, info, warn};
use samael::idp::{CertificateParams, IdentityProvider, KeyType, Rsa};
use std::{fs, io, path::Path};

const KEY_FILE_PATH: &str = "idp_private_key.der";
const CERT_FILE_PATH: &str = "idp_certificate.der";

/// Loads or creates an IdentityProvider with certificate
pub fn load_or_create_identity_provider() -> io::Result<(IdentityProvider, Vec<u8>)> {
    // Check if certificate and key files already exist
    if Path::new(KEY_FILE_PATH).exists() && Path::new(CERT_FILE_PATH).exists() {
        info!("Loading existing IdP certificate and key from files");

        // Read key and certificate from files
        let key_der = fs::read(KEY_FILE_PATH)?;
        let cert_der = fs::read(CERT_FILE_PATH)?;

        debug!("Found key file of size: {} bytes", key_der.len());
        debug!("Found certificate file of size: {} bytes", cert_der.len());

        // Deserialize the IdentityProvider from the key DER
        match IdentityProvider::from_rsa_private_key_der(&key_der) {
            Ok(idp) => {
                info!("Successfully loaded IdP from private key");
                Ok((idp, cert_der))
            }
            Err(e) => {
                error!("Failed to deserialize IdentityProvider from key: {}", e);
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to deserialize key: {}", e),
                ))
            }
        }
    } else {
        info!("No existing IdP certificate found. Generating new IdP identity");
        // Generate new IdP identity
        let idp = match IdentityProvider::generate_new(KeyType::Rsa(Rsa::Rsa2048)) {
            Ok(idp) => idp,
            Err(e) => {
                error!("Failed to generate new IdP identity: {}", e);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to generate IdP: {}", e),
                ));
            }
        };

        // Create certificate
        let cert_params = CertificateParams {
            common_name: "My Identity Provider",
            issuer_name: "My Identity Provider",
            days_until_expiration: 1000,
        };

        let cert_der = match idp.create_certificate(&cert_params) {
            Ok(cert) => cert,
            Err(e) => {
                error!("Failed to create certificate: {}", e);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to create certificate: {}", e),
                ));
            }
        };

        // Save to files for future use
        match persist_idp_identity(&idp, &cert_der) {
            Ok(_) => {
                info!("Successfully saved IdP identity to disk");
                Ok((idp, cert_der))
            }
            Err(e) => {
                warn!("Failed to persist IdP identity: {}", e);
                warn!("Continuing with generated identity, but it won't be persisted");
                Ok((idp, cert_der)) // Still return the identity even if persistence fails
            }
        }
    }
}

/// Persists the IdP identity to disk
fn persist_idp_identity(idp: &IdentityProvider, cert_der: &[u8]) -> io::Result<()> {
    debug!("Persisting IdP identity to disk");

    // Get the RSA private key in DER format
    let key_der = match idp.export_private_key_der() {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to get private key DER from IdentityProvider: {}", e);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to get private key DER: {}", e),
            ));
        }
    };

    debug!("Writing private key to {}", KEY_FILE_PATH);
    fs::write(KEY_FILE_PATH, key_der)?;

    // Save certificate
    debug!("Writing certificate to {}", CERT_FILE_PATH);
    fs::write(CERT_FILE_PATH, cert_der)?;

    info!("IdP identity successfully persisted to disk");
    Ok(())
}

