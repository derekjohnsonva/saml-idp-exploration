use actix_web::{web, HttpResponse, Responder};
use base64::engine::general_purpose;
use base64::Engine as _;
use log::{debug, error, info, trace, warn};
use samael::idp::response_builder::ResponseAttribute;
use samael::idp::sp_extractor::RequiredAttribute;
use samael::idp::IdentityProvider;
use samael::schema::{AuthnRequest, Response};
use samael::traits::ToXml;
use std::borrow::Borrow;

use crate::handlers::response_builder::sign_authn_response;
use crate::models::request::{IdpInitiatedQuery, SamlRequest, SsoQuery};
use crate::models::state::AppState;

pub async fn handle_sso(
    query: web::Query<SsoQuery>,
    state: web::Data<AppState>,
    saml_request: Option<web::Form<SamlRequest>>,
) -> impl Responder {
    info!("Handling SP-initiated SSO request");

    // Extract userId
    let user_id = query.user_id.clone();
    if user_id.is_empty() {
        warn!("Missing userId in SP-initiated SSO request");
        return HttpResponse::BadRequest().body("Missing userId parameter");
    }

    debug!("Processing SSO for user: {}", user_id);

    // Decode SAML request
    let authn_request = match saml_request.borrow() {
        Some(form) => {
            // Handle POST request
            debug!("Handling POST binding SAML request");
            let decoded = match general_purpose::STANDARD.decode(&form.saml_request) {
                Ok(data) => data,
                Err(e) => {
                    error!("Failed to decode SAML request: {}", e);
                    return HttpResponse::BadRequest().body("Invalid SAML request encoding");
                }
            };

            let xml = match String::from_utf8(decoded) {
                Ok(xml_str) => xml_str,
                Err(e) => {
                    error!("Failed to convert decoded SAML request to UTF-8: {}", e);
                    return HttpResponse::BadRequest().body("Invalid SAML request format");
                }
            };

            debug!("Parsing SAML AuthnRequest");
            let request: AuthnRequest = match xml.parse() {
                Ok(req) => req,
                Err(e) => {
                    error!("Failed to parse SAML AuthnRequest: {}", e);
                    return HttpResponse::BadRequest().body("Invalid SAML AuthnRequest");
                }
            };
            request
        }
        None => {
            // Handle GET request for redirect binding
            if query.saml_request.is_some() {
                debug!("Handling GET binding SAML request");
                // Decode and inflate the request
                // Implementation needed for deflate decompression
                // ...
                error!("Redirect binding not implemented yet");
                todo!("Implement SAML request decoding for redirect binding")
            } else {
                warn!("Missing SAMLRequest parameter");
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

    debug!(
        "AuthnRequest details - Audience: {:?}, ACS URL: {}, ID: {}",
        audience, acs_url, in_response_to
    );

    // Create user attributes
    let email = format!("{}@example.com", user_id);
    let attributes = create_user_attributes(&user_id, &email);

    debug!("Signing SAML response");
    let authn_response_fields = SignAuthnResponseFields {
        idp_x509_cert_der: &state.cert_der,
        subject_name_id: &user_id,
        audience: &audience.unwrap(),
        acs_url: &acs_url,
        issuer: &state.idp_entity_id,
        in_response_to_id: Some(in_response_to),
        attributes: &attributes,
    };

    // Sign the response
    let response = match sign_authn_response_with_config(&state.idp, authn_response_fields) {
        Ok(resp) => {
            debug!("Successfully signed SAML response with ID: {}", resp.id);
            resp
        }
        Err(e) => {
            error!("Failed to sign SAML response: {}", e);
            return HttpResponse::InternalServerError()
                .body(format!("Failed to create SAML response: {}", e));
        }
    };

    info!("Sending SAML response to {}", acs_url);
    // Create and return HTML form with SAML response
    create_saml_post_form(&response, &acs_url, &relay_state)
}

pub async fn handle_idp_initiated_sso(
    query: web::Query<IdpInitiatedQuery>,
    state: web::Data<AppState>,
) -> impl Responder {
    info!("Handling IdP-initiated SSO request");

    // Extract userId
    let user_id = query.user_id.clone();
    if user_id.is_empty() {
        warn!("Missing userId in IdP-initiated SSO request");
        return HttpResponse::BadRequest().body("Missing userId parameter");
    }

    debug!("Processing IdP-initiated SSO for user: {}", user_id);

    // Get relay state if provided
    let relay_state = query.relay_state.clone().unwrap_or_default();

    // Create user attributes
    let email = format!("{}@example.com", user_id);
    let attributes = create_user_attributes(&user_id, &email);

    // For IdP-initiated flows, we use an empty string for InResponseTo

    debug!(
        "IdP-initiated SSO to SP entity: {}, ACS URL: {}",
        state.sp_entity_id, state.sp_acs_url
    );

    debug!("Signing SAML response for IdP-initiated SSO");
    let authn_response_fields = SignAuthnResponseFields {
        idp_x509_cert_der: &state.cert_der,
        subject_name_id: &user_id,
        audience: &state.sp_entity_id,
        acs_url: &state.sp_acs_url,
        issuer: &state.idp_entity_id,
        in_response_to_id: None,
        attributes: &attributes,
    };
    // Sign the response
    let response = match sign_authn_response_with_config(&state.idp, authn_response_fields) {
        Ok(resp) => {
            debug!("Successfully signed SAML response with ID: {}", resp.id);
            resp
        }
        Err(e) => {
            error!("Failed to sign SAML response: {}", e);
            return HttpResponse::InternalServerError()
                .body(format!("Failed to create SAML response: {}", e));
        }
    };

    info!(
        "Sending IdP-initiated SAML response to {}",
        state.sp_acs_url
    );
    // Create and return HTML form with SAML response
    create_saml_post_form(&response, &state.sp_acs_url, &relay_state)
}

// Helper function to create user attributes
fn create_user_attributes<'a>(user_id: &'a str, email: &'a str) -> Vec<ResponseAttribute<'a>> {
    // Extract first and last name from username (for demo purposes)
    // TODO: Remove this
    let (first_name, last_name) = if user_id.contains('.') {
        let parts: Vec<&str> = user_id.split('.').collect();
        if parts.len() > 1 {
            (parts[0], parts[1])
        } else {
            (parts[0], "User")
        }
    } else {
        ("First", "Last")
    };

    // Format matches Okta's requested attributes from SP metadata
    vec![
        // Required attributes according to Okta SP metadata
        ResponseAttribute {
            required_attribute: RequiredAttribute {
                name: "firstName".to_string(),
                format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()),
            },
            value: first_name,
        },
        ResponseAttribute {
            required_attribute: RequiredAttribute {
                name: "lastName".to_string(),
                format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()),
            },
            value: last_name,
        },
        ResponseAttribute {
            required_attribute: RequiredAttribute {
                name: "email".to_string(),
                format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()),
            },
            value: email,
        },
        // Optional attribute
        ResponseAttribute {
            required_attribute: RequiredAttribute {
                name: "mobilePhone".to_string(),
                format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()),
            },
            value: "555-123-4567", // Example value
        },
    ]
}
/// Fields to the sign_auth_response method
struct SignAuthnResponseFields<'a> {
    idp_x509_cert_der: &'a [u8],
    subject_name_id: &'a str,
    audience: &'a str,
    acs_url: &'a str,
    issuer: &'a str,
    in_response_to_id: Option<String>,
    attributes: &'a [ResponseAttribute<'a>],
}

// Custom function to handle response signing with extra options
fn sign_authn_response_with_config(
    idp: &IdentityProvider,
    fields: SignAuthnResponseFields,
) -> Result<Response, Box<dyn std::error::Error>> {
    // Use the standard signing method which already returns a Response
    let response = sign_authn_response(
        idp,
        fields.idp_x509_cert_der,
        fields.subject_name_id,
        fields.audience,
        fields.acs_url,
        fields.issuer,
        fields.in_response_to_id,
        fields.attributes,
    )?;

    debug!("Generated response ID: {}", response.id);
    trace!("Response: {:?}", response);
    Ok(response)
}

// Helper function to create HTML form for POST binding
fn create_saml_post_form(response: &Response, acs_url: &str, relay_state: &str) -> HttpResponse {
    // Convert to XML and encode
    let response_xml = response.to_string().unwrap();

    // Log the final response XML for debugging
    // debug!("Final signed response XML: {}", response_xml);
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
