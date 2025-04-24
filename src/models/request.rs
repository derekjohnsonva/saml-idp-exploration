use serde::Deserialize;

#[derive(Deserialize)]
pub struct SsoQuery {
    pub user_id: String,
    pub saml_request: Option<String>,
    pub relay_state: Option<String>,
}

#[derive(Deserialize)]
pub struct IdpInitiatedQuery {
    pub user_id: String,
    pub relay_state: Option<String>,
}

#[derive(Deserialize)]
pub struct SamlRequest {
    pub saml_request: String,
    pub relay_state: Option<String>,
}

