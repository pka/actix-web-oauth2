#[macro_use]
extern crate serde_derive;
use actix_session::{CookieSession, Session};
use actix_web::http::header;
use actix_web::{web, App, HttpResponse, HttpServer};
use http::{HeaderMap, Method};
use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;
use oauth2::{
    AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
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
    // Create a PKCE code verifier and SHA-256 encode it as a code challenge.
    let (pkce_code_challenge, _pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();
    // Generate the authorization URL to which we'll redirect the user.
    let (auth_url, _csrf_token) = &data
        .oauth
        .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
        .add_scope(Scope::new("read_user".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_code_challenge)
        .url();

    HttpResponse::Found()
        .header(header::LOCATION, auth_url.to_string())
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
    let url = Url::parse(
        format!(
            "{}/user?access_token={}",
            api_base_url,
            access_token.secret()
        )
        .as_str(),
    )
    .unwrap();
    let resp = http_client(oauth2::HttpRequest {
        url,
        method: Method::GET,
        headers: HeaderMap::new(),
        body: Vec::new(),
    })
    .expect("Request failed");
    serde_json::from_slice(&resp.body).unwrap()
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
        .request(http_client)
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

#[actix_rt::main]
async fn main() {
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
        let auth_url = AuthUrl::new(format!("https://{}/oauth/authorize", oauthserver))
            .expect("Invalid authorization endpoint URL");
        let token_url = TokenUrl::new(format!("https://{}/oauth/token", oauthserver))
            .expect("Invalid token endpoint URL");
        let api_base_url = format!("https://{}/api/v4", oauthserver);

        // Set up the config for the OAuth2 process.
        let client = BasicClient::new(
            gitlab_client_id,
            Some(gitlab_client_secret),
            auth_url,
            Some(token_url),
        )
        // This example will be running its own server at 127.0.0.1:5000.
        .set_redirect_url(
            RedirectUrl::new("http://127.0.0.1:5000/auth".to_string())
                .expect("Invalid redirect URL"),
        );

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
    .await
    .unwrap();
}
