#[macro_use]
extern crate serde_derive;
use actix_session::{CookieSession, Session};
use actix_web::http::header;
use actix_web::{web, App, HttpResponse, HttpServer};
use oauth2::basic::BasicClient;
use oauth2::prelude::*;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl,
};
use std::env;
use url::Url;

struct AppState {
    oauth: BasicClient,
}

fn index(session: Session) -> HttpResponse {
    let link = if let Some(_login) = session.get::<bool>("login").unwrap() {
        "logout"
    } else {
        "login"
    };

    let html = format!(
        r#"<html>
        <head><title>OAuth2 Test</title></head>
        <body>
            <a href="/{}">{}</a>
        </body>
    </html>"#,
        link, link
    );

    HttpResponse::Ok().body(html)
}

fn login(data: web::Data<AppState>) -> HttpResponse {
    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, _csrf_state) = &data.oauth.authorize_url(CsrfToken::new_random);
    HttpResponse::Found()
        .header(header::LOCATION, authorize_url.to_string())
        .finish()
}

fn logout(session: Session) -> HttpResponse {
    session.remove("login");
    HttpResponse::Found()
        .header(header::LOCATION, "/".to_string())
        .finish()
}

#[derive(Deserialize)]
pub struct AuthRequest {
    code: String,
    state: String,
    scope: String,
}

fn auth(
    session: Session,
    data: web::Data<AppState>,
    params: web::Query<AuthRequest>,
) -> HttpResponse {
    let code = AuthorizationCode::new(params.code.clone());
    let state = CsrfToken::new(params.state.clone());
    let _scope = params.scope.clone();

    // Exchange the code with a token.
    let token = &data.oauth.exchange_code(code);

    session.set("login", true).unwrap();

    let html = format!(
        r#"<html>
        <head><title>OAuth2 Test</title></head>
        <body>
            Google returned the following state:
            <pre>{}</pre>
            Google returned the following token:
            <pre>{:?}</pre>
        </body>
    </html>"#,
        state.secret(),
        token
    );
    HttpResponse::Ok().body(html)
}

#[actix_rt::main]
async fn main() {
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
            .data(AppState { oauth: client })
            .wrap(CookieSession::signed(&[0; 32]).secure(false))
            .route("/", web::get().to(index))
            .route("/login", web::get().to(login))
            .route("/logout", web::get().to(logout))
            .route("/auth", web::get().to(auth))
    })
    .bind("127.0.0.1:5000")
    .expect("Can not bind to port 5000")
    .run()
    .await
    .unwrap();
}
