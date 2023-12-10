use actix_files::Files;
use actix_web::{
    http::{header::ContentType, Method, StatusCode},
    middleware::Logger,
    web, App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use serde::{Deserialize, Serialize};

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

pub async fn login(req_body: web::Json<LoginBody>) -> impl Responder {
    println!("name: {}", req_body.name);
    let is_ok = req_body.name == "admin" && req_body.value == "admin";
    if is_ok {
        HttpResponse::Ok()
        .json(ResponseData {
            error_msg: "".to_owned(),
            data: "/home".to_owned(),
        })
    } else {
        HttpResponse::Ok()
        .json(ResponseData {
            error_msg: "用户密码或密码错误".to_owned(),
            data: "".to_owned(),
        })
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("starting HTTP server at http://localhost:8081");

    HttpServer::new(|| {
        App::new()
            .service(
                web::resource("/test").to(|req: HttpRequest| match *req.method() {
                    Method::GET => HttpResponse::Ok(),
                    Method::POST => HttpResponse::MethodNotAllowed(),
                    _ => HttpResponse::NotFound(),
                }),
            )
            .service(web::resource("/login").route(web::post().to(login)))
            // We allow the visitor to see an index of the images at `/images`.
            .service(Files::new("/images", "static/images/").show_files_listing())
            // Serve a tree of static files at the web root and specify the index file.
            // Note that the root path should always be defined as the last item. The paths are
            // resolved in the order they are defined. If this would be placed before the `/images`
            // path then the service for the static images would never be reached.
            .service(Files::new("/home", "./static/root/").index_file("home.html"))
            .service(Files::new("/", "./static/root/").index_file("index.html"))
            // Enable the logger.
            .wrap(Logger::default())
    })
    .bind(("127.0.0.1", 8081))?
    .run()
    .await
}
