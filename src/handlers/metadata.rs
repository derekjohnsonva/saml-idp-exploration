use actix_web::{HttpResponse, Responder, web};
use base64::Engine as _;
use base64::engine::general_purpose;
use pem;
use samael::key_info::{KeyInfo, X509Data};
use samael::metadata::{Endpoint, EntityDescriptor, IdpSsoDescriptor, KeyDescriptor};
use samael::metadata::{HTTP_POST_BINDING, HTTP_REDIRECT_BINDING};
use samael::traits::ToXml;

use crate::models::state::AppState;

pub async fn metadata(state: web::Data<AppState>) -> impl Responder {
    let cert_b64 = general_purpose::STANDARD.encode(&state.cert_der);

    let key_descriptor = KeyDescriptor {
        key_use: Some("signing".to_string()),
        key_info: KeyInfo {
            id: None,
            x509_data: Some(X509Data {
                certificates: vec![cert_b64],
            }),
        },
        encryption_methods: None,
    };
    let sso_service_endpoint = format!("{}/sso", state.idp_entity_id);
    let idp_descriptor = IdpSsoDescriptor {
        protocol_support_enumeration: Some("urn:oasis:names:tc:SAML:2.0:protocol".to_string()),
        key_descriptors: vec![key_descriptor],
        want_authn_requests_signed: Some(false),
        single_sign_on_services: vec![
            Endpoint {
                binding: HTTP_POST_BINDING.to_string(),
                location: sso_service_endpoint.clone(),
                response_location: None,
            },
            Endpoint {
                binding: HTTP_REDIRECT_BINDING.to_string(),
                location: sso_service_endpoint,
                response_location: None,
            },
        ],
        id: Some("idstring".to_string()),
        valid_until: None,
        cache_duration: None,
        error_url: None,
        signature: None,
        organization: None,
        contact_people: vec![],
        artifact_resolution_service: vec![],
        manage_name_id_services: vec![],
        name_id_mapping_services: vec![],
        assertion_id_request_services: vec![],
        attribute_profiles: vec![],
        attributes: vec![],
        single_logout_services: vec![],
        name_id_formats: vec![],
    };

    let entity_descriptor = EntityDescriptor {
        entity_id: Some(state.idp_entity_id.clone()),
        idp_sso_descriptors: Some(vec![idp_descriptor]),
        ..EntityDescriptor::default()
    };

    let xml = entity_descriptor.to_string().unwrap();
    HttpResponse::Ok().content_type("application/xml").body(xml)
}

/// Provides the IdP signing certificate in DER format
pub async fn certificate_der(state: web::Data<AppState>) -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/x-x509-ca-cert")
        .append_header((
            "Content-Disposition",
            "attachment; filename=\"idp-certificate.der\"",
        ))
        .body(state.cert_der.clone())
}

/// Provides the IdP signing certificate in PEM format
pub async fn certificate_pem(state: web::Data<AppState>) -> impl Responder {
    // Convert DER to PEM
    // Create a PEM with "CERTIFICATE" tag and the certificate data
    let pem_string = pem::encode(&pem::Pem::new("CERTIFICATE", state.cert_der.clone()));

    HttpResponse::Ok()
        .content_type("application/x-pem-file")
        .append_header((
            "Content-Disposition",
            "attachment; filename=\"idp-certificate.pem\"",
        ))
        .body(pem_string)
}
