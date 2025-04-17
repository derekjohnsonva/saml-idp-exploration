use actix_web::web;
use samael::idp::{CertificateParams, IdentityProvider, KeyType, Rsa};
use std::sync::Arc;

use crate::models::state::AppState;

pub fn create_app_state() -> web::Data<AppState> {
    // Generate a new identity provider with RSA key
    let idp = IdentityProvider::generate_new(KeyType::Rsa(Rsa::Rsa2048)).unwrap();

    // Create certificate
    let cert_params = CertificateParams {
        common_name: "My Identity Provider",
        issuer_name: "My Identity Provider",
        days_until_expiration: 1000,
    };
    let cert_der = idp.create_certificate(&cert_params).unwrap();

    // Create AppState with configuration
    web::Data::new(AppState {
        idp: Arc::new(idp),
        cert_der,
        idp_entity_id: "https://my-idp.example.com".to_string(),
        // Replace these with your actual SP values from the SP metadata
        sp_entity_id: "IAMShowcase".to_string(),
        sp_acs_url: "https://sptest.iamshowcase.com/acs".to_string(),
    })
}

