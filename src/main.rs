use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use base64::Engine as _;
use base64::engine::general_purpose;
use samael::idp::response_builder::ResponseAttribute;
use samael::idp::sp_extractor::RequiredAttribute;
use samael::idp::{self, CertificateParams, Rsa};
use samael::key_info::{KeyInfo, X509Data};
use samael::metadata::{Endpoint, EntityDescriptor, IdpSsoDescriptor, KeyDescriptor};
use samael::metadata::{HTTP_POST_BINDING, HTTP_REDIRECT_BINDING};
use samael::schema::AuthnRequest;
use samael::traits::ToXml;
use std::borrow::Borrow;
use std::sync::Arc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // openssl_probe::init_openssl_env_vars();

    let idp = idp::IdentityProvider::generate_new(idp::KeyType::Rsa(Rsa::Rsa2048)).unwrap();
    let cert_params = CertificateParams {
        common_name: "My Identity Provider",
        issuer_name: "My Identity Provider",
        days_until_expiration: 1000,
    };
    let cert_der = idp.create_certificate(&cert_params).unwrap();

    let app_state = web::Data::new(AppState {
        idp: Arc::new(idp),
        cert_der,
        idp_entity_id: "https://my-idp.example.com".to_string(),
        // Replace these with your actual SP values from the SP metadata
        sp_entity_id: "IAMShowcase".to_string(),
        sp_acs_url: "https://sptest.iamshowcase.com/acs".to_string(),
    });
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .route("/sso", web::get().to(handle_sso))
            .route("/sso", web::post().to(handle_sso))
            .route("/idp-init", web::get().to(handle_idp_initiated_sso))
            .route("/metadata", web::get().to(metadata))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

struct AppState {
    idp: Arc<idp::IdentityProvider>,
    cert_der: Vec<u8>,
    idp_entity_id: String,
    // Default values for the SP (you'll need to update these with your actual SP values)
    sp_entity_id: String,
    sp_acs_url: String,
}

#[derive(serde::Deserialize)]
struct SsoQuery {
    user_id: String,
    saml_request: Option<String>,
    relay_state: Option<String>,
}

#[derive(serde::Deserialize)]
struct IdpInitiatedQuery {
    user_id: String,
    relay_state: Option<String>,
    target_url: Option<String>, // Optional target URL or page to redirect to after authentication
}

#[derive(serde::Deserialize)]
struct SamlRequest {
    saml_request: String,
    relay_state: Option<String>,
}
async fn handle_sso(
    query: web::Query<SsoQuery>,
    state: web::Data<AppState>,
    saml_request: Option<web::Form<SamlRequest>>,
) -> impl Responder {
    // Extract userId
    let user_id = query.user_id.clone();
    if user_id.is_empty() {
        return HttpResponse::BadRequest().body("Missing userId parameter");
    }

    // Decode SAML request
    let authn_request = match saml_request.borrow() {
        Some(form) => {
            // Handle POST request
            let decoded = general_purpose::STANDARD
                .decode(&form.saml_request)
                .unwrap();
            let xml = String::from_utf8(decoded).unwrap();
            let request: AuthnRequest = xml.parse().unwrap();
            request
        }
        None => {
            // Handle GET request for redirect binding
            if query.saml_request.is_some() {
                // Decode and inflate the request
                // Implementation needed for deflate decompression
                // ...
                todo!("Implement SAML request decoding for redirect binding")
            } else {
                return HttpResponse::BadRequest().body("Missing SAMLRequest parameter");
            }
        }
    };

    // Process the request and return a SAML response
    // Generate a successful response
    let relay_state = saml_request
        .as_ref()
        .and_then(|req| req.relay_state.clone())
        .or_else(|| query.relay_state.clone())
        .unwrap_or_default();

    // Extract information from the AuthnRequest
    let audience = authn_request.issuer.map(|i| i.value).unwrap_or_default();
    let acs_url = authn_request
        .assertion_consumer_service_url
        .unwrap_or_default();
    let in_response_to = authn_request.id;
    let borrowed_user_id = user_id.as_str();
    let email_string = format!("{}@example.com", borrowed_user_id);
    let user_email = email_string.as_str();
    // Create SAML response attributes
    let attributes = vec![
        ResponseAttribute {
            required_attribute: RequiredAttribute {
                name: "userId".to_string(),
                format: Some("User Id".to_string()),
            },
            value: borrowed_user_id,
        },
        ResponseAttribute {
            required_attribute: RequiredAttribute {
                name: "email".to_string(),
                format: Some("Email Address".to_string()),
            },
            value: user_email,
        },
    ];

    // Sign the response
    let response = state
        .idp
        .sign_authn_response(
            &state.cert_der,
            &user_id, // Use userId as the subject name ID
            &audience.unwrap(),
            &acs_url,
            &state.idp_entity_id,
            &in_response_to,
            &attributes,
        )
        .unwrap();

    // Convert to XML and encode
    let response_xml = response.to_string().unwrap();
    let encoded_response = general_purpose::STANDARD.encode(response_xml.as_bytes());

    // Create auto-submit form for the browser
    let form = format!(
        r#"
    <html>
        <head>
            <title>SAML Response</title>
        </head>
        <body>
            <form method="post" action="{}" id="SAMLResponseForm">
                <input type="hidden" name="SAMLResponse" value="{}" />
                <input type="hidden" name="RelayState" value="{}" />
                <input id="SAMLSubmitButton" type="submit" value="Submit" />
            </form>
            <script>
                document.getElementById('SAMLSubmitButton').style.visibility="hidden";
                document.getElementById('SAMLResponseForm').submit();
            </script>
        </body>
    </html>
    "#,
        acs_url, encoded_response, relay_state
    );
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(form)
}

async fn handle_idp_initiated_sso(
    query: web::Query<IdpInitiatedQuery>,
    state: web::Data<AppState>,
) -> impl Responder {
    // Extract userId
    let user_id = query.user_id.clone();
    if user_id.is_empty() {
        return HttpResponse::BadRequest().body("Missing userId parameter");
    }

    // Get relay state if provided
    let relay_state = query.relay_state.clone().unwrap_or_default();

    // Use the target_url as relay_state if provided
    let final_relay_state = if relay_state.is_empty() && query.target_url.is_some() {
        query.target_url.clone().unwrap()
    } else {
        relay_state
    };

    // Set up user attributes
    let borrowed_user_id = user_id.as_str();
    let email_string = format!("{}@example.com", borrowed_user_id);
    let user_email = email_string.as_str();

    // Create SAML response attributes
    let attributes = vec![
        ResponseAttribute {
            required_attribute: RequiredAttribute {
                name: "userId".to_string(),
                format: Some("User Id".to_string()),
            },
            value: borrowed_user_id,
        },
        ResponseAttribute {
            required_attribute: RequiredAttribute {
                name: "email".to_string(),
                format: Some("Email Address".to_string()),
            },
            value: user_email,
        },
    ];

    // Since there's no AuthnRequest in IdP-initiated SSO, there's no InResponseTo
    // We use a UUID or empty string instead
    let in_response_to = ""; // No InResponseTo for IdP-initiated flow

    // Sign the response
    let response = state
        .idp
        .sign_authn_response(
            &state.cert_der,
            &user_id,            // Use userId as the subject name ID
            &state.sp_entity_id, // Use the SP entity ID from configuration
            &state.sp_acs_url,   // Use the SP ACS URL from configuration
            &state.idp_entity_id,
            in_response_to,
            &attributes,
        )
        .unwrap();

    // Convert to XML and encode
    let response_xml = response.to_string().unwrap();
    let encoded_response = general_purpose::STANDARD.encode(response_xml.as_bytes());

    // Create auto-submit form for the browser
    let form = format!(
        r#"
    <html>
        <head>
            <title>SAML Response</title>
        </head>
        <body>
            <form method="post" action="{}" id="SAMLResponseForm">
                <input type="hidden" name="SAMLResponse" value="{}" />
                <input type="hidden" name="RelayState" value="{}" />
                <input id="SAMLSubmitButton" type="submit" value="Submit" />
            </form>
            <script>
                document.getElementById('SAMLSubmitButton').style.visibility="hidden";
                document.getElementById('SAMLResponseForm').submit();
            </script>
        </body>
    </html>
    "#,
        state.sp_acs_url, encoded_response, final_relay_state
    );

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(form)
}

async fn metadata(state: web::Data<AppState>) -> impl Responder {
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

    let idp_descriptor = IdpSsoDescriptor {
        protocol_support_enumeration: Some("urn:oasis:names:tc:SAML:2.0:protocol".to_string()),
        key_descriptors: vec![key_descriptor],
        want_authn_requests_signed: Some(false),
        single_sign_on_services: vec![
            Endpoint {
                binding: HTTP_POST_BINDING.to_string(),
                location: "https://your-domain.com/sso".to_string(),
                response_location: None,
            },
            Endpoint {
                binding: HTTP_REDIRECT_BINDING.to_string(),
                location: "https://your-domain.com/sso".to_string(),
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
        // Add other required fields
    };

    let entity_descriptor = EntityDescriptor {
        entity_id: Some(state.idp_entity_id.clone()),
        idp_sso_descriptors: Some(vec![idp_descriptor]),
        // Add other fields
        ..EntityDescriptor::default()
    };

    let xml = entity_descriptor.to_string().unwrap();
    HttpResponse::Ok().content_type("application/xml").body(xml)
}
