use actix_web::{HttpResponse, Responder, web};
use base64::Engine as _;
use base64::engine::general_purpose;
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

    // Create user attributes
    let email = format!("{}@example.com", user_id);
    let attributes = create_user_attributes(&user_id, &email);

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

    // Create and return HTML form with SAML response
    create_saml_post_form(&response, &acs_url, &relay_state)
}

pub async fn handle_idp_initiated_sso(
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

    // Create user attributes
    let email = format!("{}@example.com", user_id);
    let attributes = create_user_attributes(&user_id, &email);

    // Since there's no AuthnRequest in IdP-initiated SSO, there's no InResponseTo
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

    // Create and return HTML form with SAML response
    create_saml_post_form(&response, &state.sp_acs_url, &final_relay_state)
}

// Helper function to create user attributes
fn create_user_attributes<'a>(user_id: &'a str, email: &'a str) -> Vec<ResponseAttribute<'a>> {
    vec![
        ResponseAttribute {
            required_attribute: RequiredAttribute {
                name: "userId".to_string(),
                format: Some("User Id".to_string()),
            },
            value: user_id,
        },
        ResponseAttribute {
            required_attribute: RequiredAttribute {
                name: "email".to_string(),
                format: Some("Email Address".to_string()),
            },
            value: email,
        },
    ]
}

// Helper function to create HTML form for POST binding
fn create_saml_post_form(response: &Response, acs_url: &str, relay_state: &str) -> HttpResponse {
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
