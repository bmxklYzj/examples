use std::fs;

use actix_files::{Files, NamedFile};
use actix_identity::{Identity, IdentityMiddleware};
use actix_session::{config::PersistentSession, storage::CookieSessionStore, SessionMiddleware};
use actix_web::{
    cookie::{time::Duration, Key},
    error,
    http::{header::ContentType, Method, StatusCode},
    middleware::Logger,
    web, App, Error, HttpMessage as _, HttpRequest, HttpResponse, HttpServer, Responder,
};
use serde::{Deserialize, Serialize};

const ONE_MINUTE: Duration = Duration::minutes(1);

#[derive(Deserialize, Serialize)]
pub struct LoginBody {
    name: String,
    value: String,
}

#[derive(Deserialize, Serialize)]
struct ResponseData {
    error_msg: String,
    data: String,
}

async fn login(req: HttpRequest, req_body: web::Json<LoginBody>) -> impl Responder {
    println!("name: {}", req_body.name);

    Identity::login(&req.extensions(), req_body.name.to_owned()).unwrap();
    let is_ok = req_body.name == "admin" && req_body.value == "admin";
    if is_ok {
        HttpResponse::Ok().json(ResponseData {
            error_msg: "".to_owned(),
            data: "/home".to_owned(),
        })
    } else {
        HttpResponse::Ok().json(ResponseData {
            error_msg: "用户密码或密码错误".to_owned(),
            data: "".to_owned(),
        })
    }
}

async fn logout(id: Identity) -> impl Responder {
    id.logout();
    HttpResponse::Ok().json(ResponseData {
        error_msg: "".to_owned(),
        data: "/".to_owned(),
    })
}

async fn home(identity: Option<Identity>) -> impl Responder {
    if let Some(_) = identity {
        HttpResponse::build(StatusCode::OK)
            .content_type("text/html; charset=utf-8")
            .body(include_str!("../static/root/home.html"))
    } else {
        HttpResponse::Found().header("Location", "/").finish()
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let secret_key = Key::generate();

    log::info!("starting HTTP server at http://localhost:8081");

    HttpServer::new(move || {
        App::new()
            .service(
                web::resource("/test").to(|req: HttpRequest| match *req.method() {
                    Method::GET => HttpResponse::Ok(),
                    Method::POST => HttpResponse::MethodNotAllowed(),
                    _ => HttpResponse::NotFound(),
                }),
            )
            .service(web::resource("/login").route(web::post().to(login)))
            .service(web::resource("/logout").route(web::post().to(logout)))
            .service(web::resource("/home").route(web::get().to(home)))
            // .service(Files::new("/homestatic", "./static/root/").index_file("home.html"))
            // We allow the visitor to see an index of the images at `/images`.
            .service(Files::new("/images", "static/images/").show_files_listing())
            // Serve a tree of static files at the web root and specify the index file.
            // Note that the root path should always be defined as the last item. The paths are
            // resolved in the order they are defined. If this would be placed before the `/images`
            // path then the service for the static images would never be reached.
            .service(Files::new("/", "./static/root/").index_file("index.html"))
            .wrap(IdentityMiddleware::default())
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_name("bspuser".to_owned())
                    .cookie_secure(false)
                    .session_lifecycle(PersistentSession::default().session_ttl(ONE_MINUTE))
                    .build(),
            )
            // Enable the logger.
            .wrap(Logger::default())
    })
    .bind(("127.0.0.1", 8081))?
    .run()
    .await
}
