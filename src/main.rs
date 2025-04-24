use actix_web::{middleware::Logger, web, App, HttpServer};
use env_logger::Env;
use log::{debug, info};

mod cert_util;
mod config;
mod handlers;
mod models;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger
    // Set the default log level to INFO, but allow overriding via RUST_LOG environment variable
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    info!("Starting SAML IdP server");

    // Create application state
    let app_state = config::create_app_state();
    debug!("Application state created");

    // Start HTTP server
    info!("Configuring HTTP server");
    info!("Server will be available at http://127.0.0.1:8080");
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
    .bind("127.0.0.1:8080")?
    .workers(1)
    .run()
    .await
}
