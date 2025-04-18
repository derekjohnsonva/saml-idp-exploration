use actix_web::{HttpResponse, Responder, web};
use base64::Engine as _;
use base64::engine::general_purpose;
use log::{debug, error, info, warn};
use samael::idp::IdentityProvider;
use samael::idp::response_builder::ResponseAttribute;
use samael::idp::sp_extractor::RequiredAttribute;
use samael::schema::{AuthnRequest, Response};
use samael::traits::ToXml;
use std::borrow::Borrow;

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
    // Sign the response
    let response = match sign_authn_response_with_config(
        &state.idp,
        &state.cert_der,
        &user_id, // Use userId as the subject name ID
        &audience.unwrap(),
        &acs_url,
        &state.idp_entity_id,
        &in_response_to,
        &attributes,
        state.sign_assertions,
    ) {
        Ok(resp) => {
            debug!("Successfully signed SAML response");
            resp
        }
        Err(e) => {
            error!("Failed to sign SAML response: {}", e);
            return HttpResponse::InternalServerError().body("Failed to create SAML response");
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

    // Use the target_url as relay_state if provided
    let final_relay_state = if relay_state.is_empty() && query.target_url.is_some() {
        query.target_url.clone().unwrap()
    } else {
        relay_state
    };

    // Create user attributes
    let email = format!("{}@example.com", user_id);
    let attributes = create_user_attributes(&user_id, &email);

    // Since there's no AuthnRequest in IdP-initiated SSO, there's no InResponseTo
    let in_response_to = ""; // No InResponseTo for IdP-initiated flow

    debug!(
        "IdP-initiated SSO to SP entity: {}, ACS URL: {}",
        state.sp_entity_id, state.sp_acs_url
    );

    debug!("Signing SAML response for IdP-initiated SSO");
    // Sign the response
    let response = match sign_authn_response_with_config(
        &state.idp,
        &state.cert_der,
        &user_id,            // Use userId as the subject name ID
        &state.sp_entity_id, // Use the SP entity ID from configuration
        &state.sp_acs_url,   // Use the SP ACS URL from configuration
        &state.idp_entity_id,
        in_response_to,
        &attributes,
        state.sign_assertions,
    ) {
        Ok(resp) => {
            debug!("Successfully signed SAML response");
            resp
        }
        Err(e) => {
            error!("Failed to sign SAML response: {}", e);
            return HttpResponse::InternalServerError().body("Failed to create SAML response");
        }
    };

    info!(
        "Sending IdP-initiated SAML response to {}",
        state.sp_acs_url
    );
    // Create and return HTML form with SAML response
    create_saml_post_form(&response, &state.sp_acs_url, &final_relay_state)
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

// Custom function to handle response signing with extra options
fn sign_authn_response_with_config(
    idp: &IdentityProvider,
    idp_x509_cert_der: &[u8],
    subject_name_id: &str,
    audience: &str,
    acs_url: &str,
    issuer: &str,
    in_response_to_id: &str,
    attributes: &[ResponseAttribute],
    sign_assertions: bool,
) -> Result<Response, Box<dyn std::error::Error>> {
    // We don't need to build the response template separately,
    // as sign_authn_response will handle it

    // There's no direct support for signing assertions in the library,
    // so for now we're only signing the response
    if sign_assertions {
        debug!("Okta requires signed assertions, but library only supports signed responses");
        // TODO: Implement assertion signing capability
    }

    // Use the standard signing method which already returns a Response
    let response = idp.sign_authn_response(
        idp_x509_cert_der,
        subject_name_id,
        audience,
        acs_url,
        issuer,
        in_response_to_id,
        attributes,
    )?;

    Ok(response)
}

// Helper function to create HTML form for POST binding
fn create_saml_post_form(response: &Response, acs_url: &str, relay_state: &str) -> HttpResponse {
    // Convert to XML and encode
    let response_xml = response.to_string().unwrap();

    // Log the final response XML for debugging
    debug!("Final signed response XML: {}", response_xml);
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
