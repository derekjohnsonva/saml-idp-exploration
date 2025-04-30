use actix_web::{App, HttpServer, middleware::Logger, web};
use dotenv::dotenv;
use env_logger::Env;
use log::{debug, error, info};
use std::env;

mod cert_util;
mod config;
mod handlers;
mod models;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables from .env file
    dotenv().ok();

    // Initialize logger
    // Set the default log level to INFO, but allow overriding via RUST_LOG environment variable
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    info!("Starting SAML IdP server");

    // Create application state
    let app_state = match config::create_app_state() {
        Ok(state) => {
            debug!("Application state created successfully");
            state
        }
        Err(e) => {
            error!("Failed to create application state: {}", e);
            return Err(std::io::Error::other(
                format!("Failed to create application state: {}", e)
            ));
        }
    };

    // Get server host and port from environment variables
    let server_host = env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let server_port = env::var("SERVER_PORT").unwrap_or_else(|_| "8080".to_string());
    let server_addr = format!("{}:{}", server_host, server_port);

    // Start HTTP server
    info!("Configuring HTTP server");
    info!("Server will be available at http://{}", server_addr);
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default()) // Add logger middleware for HTTP requests
            .wrap(Logger::new("%a %r %s %b %{User-Agent}i %T")) // Add custom format logger
            .app_data(app_state.clone())
            .route("/", web::get().to(handlers::landing::index))
            .route("/sso", web::get().to(handlers::sso::handle_sso))
            .route("/sso", web::post().to(handlers::sso::handle_sso))
            .route(
                "/idp-init",
                web::get().to(handlers::sso::handle_idp_initiated_sso),
            )
            .route("/metadata", web::get().to(handlers::metadata::metadata))
            .route(
                "/certificate/pem",
                web::get().to(handlers::metadata::certificate_pem),
            )
            .route(
                "/certificate/der",
                web::get().to(handlers::metadata::certificate_der),
            )
    })
    .bind(&server_addr)?
    .workers(1)
    .run()
    .await
}
