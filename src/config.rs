use actix_web::web;
use log::{error, info};
use std::sync::Arc;

use crate::cert_util::load_or_create_identity_provider;
use crate::models::state::AppState;

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

    // Create AppState with configuration
    web::Data::new(AppState {
        idp: Arc::new(idp),
        cert_der,
        idp_entity_id: "https://219c-73-143-30-151.ngrok-free.app".to_string(),
        // Okta SP values from the SP metadata
        sp_entity_id: "https://www.okta.com/saml2/service-provider/spkfpnrefermtybsfvcd"
            .to_string(),
        sp_acs_url: "https://dev-50824006.okta.com/sso/saml2/0oaocmyrr91ruN6AP5d7".to_string(),
        // Okta requires signed assertions (WantAssertionsSigned="true")
        sign_assertions: true,
    })
}
