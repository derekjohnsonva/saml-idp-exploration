use actix_web::{App, HttpServer, web};

mod config;
mod handlers;
mod models;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Create application state
    let app_state = config::create_app_state();

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .route("/", web::get().to(handlers::landing::index))
            .route("/sso", web::get().to(handlers::sso::handle_sso))
            .route("/sso", web::post().to(handlers::sso::handle_sso))
            .route(
                "/idp-init",
                web::get().to(handlers::sso::handle_idp_initiated_sso),
            )
            .route("/metadata", web::get().to(handlers::metadata::metadata))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

