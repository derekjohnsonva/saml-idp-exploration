use actix_web::web;
use log::{error, info};
use std::sync::Arc;

use crate::cert_util::load_or_create_identity_provider;
use crate::models::state::AppState;
use crate::models::user::UserDatabase;

pub fn create_app_state() -> web::Data<AppState> {
    // Load or create identity provider
    let (idp, cert_der) = match load_or_create_identity_provider() {
        Ok((idp, cert)) => (idp, cert),
        Err(e) => {
            // If loading/creating fails, panic since we can't continue without an IdP
            error!("Failed to load or create identity provider: {}", e);
            panic!("Failed to initialize IdP: {}", e);
        }
    };

    info!(
        "IdP initialized with certificate of size: {} bytes",
        cert_der.len()
    );

    // Load user database
    let user_database = match UserDatabase::load_from_file("users.yaml") {
        Ok(db) => {
            info!("Loaded user database with {} users", db.users.len());
            db
        },
        Err(e) => {
            error!("Failed to load user database: {}", e);
            panic!("Failed to load user database: {}", e);
        }
    };

    // Create AppState with configuration
    web::Data::new(AppState {
        idp: Arc::new(idp),
        cert_der,
        idp_entity_id: "https://55dd-34-103-75-72.ngrok-free.app".to_string(),
        // Okta SP values from the SP metadata
        sp_entity_id: "https://www.okta.com/saml2/service-provider/spkfpnrefermtybsfvcd"
            .to_string(),
        sp_acs_url: "https://dev-50824006.okta.com/sso/saml2/0oaocmyrr91ruN6AP5d7".to_string(),
        user_database,
    })
}
