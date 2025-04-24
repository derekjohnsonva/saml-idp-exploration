use chrono::Utc;
use log::debug;
use samael::attribute::{Attribute, AttributeValue};
use samael::crypto;
use samael::idp::response_builder::ResponseAttribute;
use samael::idp::IdentityProvider;
use samael::schema::{
    Assertion, AttributeStatement, AudienceRestriction, AuthnContext, AuthnContextClassRef,
    AuthnStatement, Conditions, Issuer, Response, Status, StatusCode, Subject, SubjectConfirmation,
    SubjectConfirmationData, SubjectNameID,
};
use samael::signature::Signature;
use samael::traits::ToXml;
use std::str::FromStr;

fn build_conditions(audience: &str) -> Conditions {
    Conditions {
        not_before: None,
        not_on_or_after: None,
        audience_restrictions: Some(vec![AudienceRestriction {
            audience: vec![audience.to_string()],
        }]),
        one_time_use: None,
        proxy_restriction: None,
    }
}

fn build_authn_statement(class: &str) -> AuthnStatement {
    AuthnStatement {
        authn_instant: Some(Utc::now()),
        session_index: None,
        session_not_on_or_after: None,
        subject_locality: None,
        authn_context: Some(AuthnContext {
            value: Some(AuthnContextClassRef {
                value: Some(class.to_string()),
            }),
        }),
    }
}

fn build_attributes(formats_names_values: &[ResponseAttribute]) -> Vec<Attribute> {
    formats_names_values
        .iter()
        .map(|attr| Attribute {
            friendly_name: None,
            name: Some(attr.required_attribute.name.clone()),
            name_format: attr.required_attribute.format.clone(),
            values: vec![AttributeValue {
                attribute_type: Some("xs:string".to_string()),
                value: Some(attr.value.to_string()),
            }],
        })
        .collect()
}

fn build_assertion(
    name_id: &str,
    request_id: Option<String>,
    issuer: Issuer,
    recipient: &str,
    audience: &str,
    attributes: &[ResponseAttribute],
) -> Assertion {
    let assertion_id = crypto::gen_saml_assertion_id();

    Assertion {
        id: assertion_id,
        issue_instant: Utc::now(),
        version: "2.0".to_string(),
        issuer,
        signature: None,
        subject: Some(Subject {
            name_id: Some(SubjectNameID {
                format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified".to_string()),
                value: name_id.to_owned(),
            }),
            subject_confirmations: Some(vec![SubjectConfirmation {
                method: Some("urn:oasis:names:tc:SAML:2.0:cm:bearer".to_string()),
                name_id: None,
                subject_confirmation_data: Some(SubjectConfirmationData {
                    not_before: None,
                    not_on_or_after: None,
                    recipient: Some(recipient.to_owned()),
                    in_response_to: request_id,
                    address: None,
                    content: None,
                }),
            }]),
        }),
        conditions: Some(build_conditions(audience)),
        authn_statements: Some(vec![build_authn_statement(
            "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
        )]),
        attribute_statements: Some(vec![AttributeStatement {
            attributes: build_attributes(attributes),
        }]),
    }
}

fn build_response(
    name_id: &str,
    issuer: &str,
    request_id: Option<String>,
    attributes: &[ResponseAttribute],
    destination: &str,
    audience: &str,
    x509_cert: &[u8],
) -> Response {
    let issuer = Issuer {
        value: Some(issuer.to_string()),
        ..Default::default()
    };

    let response_id = crypto::gen_saml_response_id();

    Response {
        id: response_id.clone(),
        // TODO: Figure out if we can do this without cloning
        in_response_to: request_id.clone(),
        version: "2.0".to_string(),
        issue_instant: Utc::now(),
        destination: Some(destination.to_string()),
        consent: None,
        issuer: Some(issuer.clone()),
        signature: Some(Signature::template(&response_id, x509_cert)),
        status: Some(Status {
            status_code: StatusCode {
                value: Some("urn:oasis:names:tc:SAML:2.0:status:Success".to_string()),
            },
            status_message: None,
            status_detail: None,
        }),
        encrypted_assertion: None,
        assertion: Some(build_assertion(
            name_id,
            request_id,
            issuer,
            destination,
            audience,
            attributes,
        )),
    }
}

pub fn build_response_template(
    cert_der: &[u8],
    name_id: &str,
    audience: &str,
    issuer: &str,
    acs_url: &str,
    request_id: Option<String>,
    attributes: &[ResponseAttribute],
) -> Response {
    build_response(
        name_id, issuer, request_id, attributes, acs_url, audience, cert_der,
    )
}
pub fn sign_authn_response(
    idp: &IdentityProvider,
    idp_x509_cert_der: &[u8],
    subject_name_id: &str,
    audience: &str,
    acs_url: &str,
    issuer: &str,
    in_response_to_id: Option<String>,
    attributes: &[ResponseAttribute],
) -> Result<Response, Box<dyn std::error::Error>> {
    let response = build_response_template(
        idp_x509_cert_der,
        subject_name_id,
        audience,
        issuer,
        acs_url,
        in_response_to_id,
        attributes,
    );

    let response_xml_unsigned = response.to_string()?;
    debug!(
        "Created the unsigned response. Value is {:?}",
        response_xml_unsigned
    );
    let signed_xml = crypto::sign_xml(
        response_xml_unsigned.as_str(),
        idp.export_private_key_der()?.as_slice(),
    )?;
    debug!("signed the response");
    let signed_response = samael::schema::Response::from_str(signed_xml.as_str())?;
    Ok(signed_response)
}
