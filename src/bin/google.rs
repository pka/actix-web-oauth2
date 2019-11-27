#[macro_use]
extern crate serde_derive;
use actix_web::http::header;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use oauth2::basic::BasicClient;
use oauth2::prelude::*;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl,
};
use std::env;
use url::Url;

fn greet(req: HttpRequest) -> impl Responder {
    let name = req.match_info().get("name").unwrap_or("World");
    format!("Hello {}!", &name)
}

struct AppState {
    client: BasicClient,
}

fn login(data: web::Data<AppState>) -> impl Responder {
    let client = &data.client;
    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, _csrf_state) = client.authorize_url(CsrfToken::new_random);
    HttpResponse::Found()
        .header(header::LOCATION, authorize_url.to_string())
        .finish()
}

#[derive(Deserialize)]
pub struct AuthRequest {
    code: String,
    state: String,
    scope: String,
}

fn auth(data: web::Data<AppState>, params: web::Query<AuthRequest>) -> impl Responder {
    let client = &data.client;

    let code = AuthorizationCode::new(params.code.clone());
    let state = CsrfToken::new(params.state.clone());
    let _scope = params.scope.clone();

    println!("Google returned the following state:\n{}", state.secret(),);
    // (expected `{}`)\n", csrf_state.secret()

    // Exchange the code with a token.
    let token = client.exchange_code(code);

    println!("Google returned the following token:\n{:?}\n", token);

    HttpResponse::Ok().body("Authentication Successful")
}

fn main() {
    HttpServer::new(|| {
        let google_client_id = ClientId::new(
            env::var("GOOGLE_CLIENT_ID")
                .expect("Missing the GOOGLE_CLIENT_ID environment variable."),
        );
        let google_client_secret = ClientSecret::new(
            env::var("GOOGLE_CLIENT_SECRET")
                .expect("Missing the GOOGLE_CLIENT_SECRET environment variable."),
        );
        let auth_url = AuthUrl::new(
            Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
                .expect("Invalid authorization endpoint URL"),
        );
        let token_url = TokenUrl::new(
            Url::parse("https://www.googleapis.com/oauth2/v3/token")
                .expect("Invalid token endpoint URL"),
        );

        // Set up the config for the Google OAuth2 process.
        let client = BasicClient::new(
            google_client_id,
            Some(google_client_secret),
            auth_url,
            Some(token_url),
        )
        // This example is requesting access to the "calendar" features and the user's profile.
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/calendar".to_string(),
        ))
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/plus.me".to_string(),
        ))
        // This example will be running its own server at 127.0.0.1:5000.
        .set_redirect_url(RedirectUrl::new(
            Url::parse("http://127.0.0.1:5000/auth").expect("Invalid redirect URL"),
        ));

        App::new()
            .data(AppState { client: client })
            .route("/", web::get().to(greet))
            .route("/login", web::get().to(login))
            .route("/auth", web::get().to(auth))
    })
    .bind("127.0.0.1:5000")
    .expect("Can not bind to port 5000")
    .run()
    .unwrap();
}
