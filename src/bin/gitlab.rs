#[macro_use]
extern crate serde_derive;
use actix_session::{CookieSession, Session};
use actix_web::http::header;
use actix_web::{web, App, HttpResponse, HttpServer};
use curl::easy::Easy;
use oauth2::basic::BasicClient;
use oauth2::prelude::*;
use oauth2::{
    AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use std::env;
use url::Url;

struct AppState {
    oauth: BasicClient,
    api_base_url: String,
}

fn index(session: Session) -> HttpResponse {
    let login = session.get::<String>("login").unwrap();
    let link = if login.is_some() { "logout" } else { "login" };

    let html = format!(
        r#"<html>
        <head><title>OAuth2 Test</title></head>
        <body>
            {} <a href="/{}">{}</a>
        </body>
    </html>"#,
        login.unwrap_or("".to_string()),
        link,
        link
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

#[derive(Deserialize, Debug)]
pub struct UserInfo {
    id: u64,
    name: String,
    username: String,
    state: String,
    avatar_url: String,
    web_url: String,
    created_at: String,
    bio: String,
    location: String,
    skype: String,
    linkedin: String,
    twitter: String,
    website_url: String,
    organization: String,
    last_sign_in_at: String,
    confirmed_at: String,
    last_activity_on: String,
    email: String,
    theme_id: u32,
    color_scheme_id: u32,
    projects_limit: u32,
    current_sign_in_at: String,
    identities: Vec<String>,
    can_create_group: bool,
    can_create_project: bool,
    two_factor_enabled: bool,
    external: bool,
    private_profile: bool,
    is_admin: bool,
}

fn read_user(api_base_url: &str, access_token: &AccessToken) -> UserInfo {
    let mut data = Vec::new();
    let mut handle = Easy::new();
    handle
        .url(
            format!(
                "{}/user?access_token={}",
                api_base_url,
                access_token.secret()
            )
            .as_str(),
        )
        .unwrap();
    {
        let mut transfer = handle.transfer();
        transfer
            .write_function(|new_data| {
                data.extend_from_slice(new_data);
                Ok(new_data.len())
            })
            .unwrap();
        transfer.perform().unwrap();
    }
    serde_json::from_slice(&data).unwrap()
}

#[derive(Deserialize)]
struct AuthRequest {
    code: String,
    state: String,
}

fn auth(
    session: Session,
    data: web::Data<AppState>,
    params: web::Query<AuthRequest>,
) -> HttpResponse {
    let code = AuthorizationCode::new(params.code.clone());
    let _state = CsrfToken::new(params.state.clone());

    // Exchange the code with a token.
    let token = &data
        .oauth
        .exchange_code(code)
        .expect("exchange_code failed");

    let user_info = read_user(&data.api_base_url, token.access_token());

    session.set("login", user_info.username.clone()).unwrap();

    let html = format!(
        r#"<html>
        <head><title>OAuth2 Test</title></head>
        <body>
            Gitlab user info:
            <pre>{:?}</pre>
            <a href="/">Home</a>
        </body>
    </html>"#,
        user_info
    );
    HttpResponse::Ok().body(html)
}

fn main() {
    HttpServer::new(|| {
        let gitlab_client_id = ClientId::new(
            env::var("GITLAB_CLIENT_ID")
                .expect("Missing the GITLAB_CLIENT_ID environment variable."),
        );
        let gitlab_client_secret = ClientSecret::new(
            env::var("GITLAB_CLIENT_SECRET")
                .expect("Missing the GITLAB_CLIENT_SECRET environment variable."),
        );
        let oauthserver =
            env::var("GITLAB_SERVER").expect("Missing the GITLAB_SERVER environment variable.");
        let auth_url = AuthUrl::new(
            Url::parse(format!("https://{}/oauth/authorize", oauthserver).as_str())
                .expect("Invalid authorization endpoint URL"),
        );
        let token_url = TokenUrl::new(
            Url::parse(format!("https://{}/oauth/token", oauthserver).as_str())
                .expect("Invalid token endpoint URL"),
        );
        let api_base_url = format!("https://{}/api/v4", oauthserver);

        // Set up the config for the OAuth2 process.
        let client = BasicClient::new(
            gitlab_client_id,
            Some(gitlab_client_secret),
            auth_url,
            Some(token_url),
        )
        .add_scope(Scope::new("read_user".to_string()))
        // This example will be running its own server at 127.0.0.1:5000.
        .set_redirect_url(RedirectUrl::new(
            Url::parse("http://127.0.0.1:5000/auth").expect("Invalid redirect URL"),
        ));

        App::new()
            .data(AppState {
                oauth: client,
                api_base_url,
            })
            .wrap(CookieSession::signed(&[0; 32]).secure(false))
            .route("/", web::get().to(index))
            .route("/login", web::get().to(login))
            .route("/logout", web::get().to(logout))
            .route("/auth", web::get().to(auth))
    })
    .bind("127.0.0.1:5000")
    .expect("Can not bind to port 5000")
    .run()
    .unwrap();
}
