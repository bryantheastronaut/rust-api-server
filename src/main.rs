#![feature(peek)]

#[macro_use]
extern crate nickel;
extern crate rustc_serialize;

#[macro_use(bson, doc)]
extern crate bson;
extern crate crypto;
extern crate jwt;
extern crate hyper;

use nickel::{Nickel, JsonBody, Request, Response, HttpRouter, MiddlewareResult};
use hyper::header;
use hyper::header::{Authorization, Bearer};
use hyper::method::Method;

use bson::{Bson, Document};
use bson::oid::ObjectId;

use rustc_serialize::json::{Json, ToJson};
use rustc_serialize::base64;
use rustc_serialize::base64::FromBase64;

// jwt auth stuff
use std::default::Default;
use crypto::sha2::Sha256;
use jwt::{Header, Registered, Token};

static AUTH_SECRET: &'static str = "cool_secret_you_can_never_hax";


#[derive(RustcEncodable, RustcDecodable)]
struct User {
    firstname: String,
    lastname: String,
    email: String
}

struct UserLogin {
    email: String,
    password: String
}

fn authenticator<'mw>(req: &mut Request, res: &mut Response) -> MiddlewareResult<'mw> {
    if req.origin.method.to_string() == "OPTIONS".to_string() {
        res.next_middleware()
    } else {
        if req.origin.uri.to_string() == "/login".to_string() {
            res.next_middleware()
        } else {
            // get full auth header from incoming req
            let auth_header = match req.origin.headers.get::<Authorization<Bearer>>() {
                Some(header) => header,
                None => panic!("No auth header was found")
            };

            let jwt = header::HeaderFormatter(auth_header).to_string();
            // ignore the Bearer part and just get the token
            let jwt_slice = &jwt[7..];
            let token = Token::<Header, Registered>::parse(jwt_slice).unwrap();
            let secret = AUTH_SECRET.as_bytes();
            if token.verify(&secret, Sha256::new()) {
                res.next_middleware()
            } else {
                res.error(Forbidden, "Access denied")
            }
        }
    }
}

fn main() {
    let mut server = Nickel::new();
    let mut router = Nickel::router();

    server.utilize(authenticator);

    server.get("/", middleware!("Home page!"));
    server.get("/test", middleware!("This is the test page!"));
    server.get("**", middleware!("Any other page"));
    server.listen("127.0.0.1:1337");
}
