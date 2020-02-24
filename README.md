Actix web OAuth2 examples
=========================

This repo contains examples for using OAuth2 authentication in an [Actix Web](https://actix.rs/) application.

Current versions:

- Actix Web 2.0
- [OAuth2](https://github.com/ramosbugs/oauth2-rs) 3.0


## Running the examples

Create credentials with origin URL http://127.0.0.1:5000 and redirect URL http://127.0.0.1:5000/auth

### OAuth2 login with Google

Create credentials at https://console.developers.google.com/apis/credentials

```sh
GOOGLE_CLIENT_ID=xxx GOOGLE_CLIENT_SECRET=yyy cargo run --bin google
x-www-browser http://127.0.0.1:5000/
```

### OAuth2 login with Gitlab

Create credentials at https://gitlab.example.com/admin/applications

```sh
GITLAB_SERVER=gitlab.example.com GITLAB_CLIENT_ID=xxx GITLAB_CLIENT_SECRET=yyy cargo run --bin gitlab
x-www-browser http://127.0.0.1:5000/
```
