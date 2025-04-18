use actix_web::{HttpResponse, Responder};
use log::info;

/// Handles the root path, showing a landing page for the SAML Demo IdP
pub async fn index() -> impl Responder {
    info!("Serving landing page");
    let html = r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SAML Demo IdP</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                background-color: #f5f5f5;
            }
            .container {
                text-align: center;
                background-color: white;
                border-radius: 8px;
                padding: 40px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                max-width: 600px;
            }
            h1 {
                color: #333;
                margin-bottom: 20px;
            }
            p {
                color: #666;
                line-height: 1.6;
                margin-bottom: 30px;
            }
            .links {
                margin-top: 30px;
            }
            .links a {
                display: inline-block;
                margin: 0 10px;
                color: #0066cc;
                text-decoration: none;
            }
            .links a:hover {
                text-decoration: underline;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome to the SAML Demo IdP</h1>
            <p>This is a demonstration Identity Provider (IdP) for SAML authentication.</p>
            <div class="links">
                <a href="/metadata">View IdP Metadata</a>
                <a href="/idp-init?user_id=testuser">Initiate SSO (Test User)</a>
                <a href="/certificate/pem">Download Certificate (PEM)</a>
                <a href="/certificate/der">Download Certificate (DER)</a>
            </div>
        </div>
    </body>
    </html>
    "#;

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}
