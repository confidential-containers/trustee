use actix_web::{web, HttpResponse};
use kbs_types::{Challenge, Request};

/// This handler uses json extractor
pub(crate) async fn auth(request: web::Json<Request>) -> HttpResponse {
    println!("request: {:?}", &request);

    HttpResponse::Ok().json(Challenge {
        nonce: "nonce".to_string(),
        extra_params: "extra_params".to_string(),
    })
}
