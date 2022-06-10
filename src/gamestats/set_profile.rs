use hyper::{Body, Request, Response};
use log::error;
use crate::backend::backends::BackendsRef;

pub(crate) async fn gs_set_profile(req: Request<Body>, backends: BackendsRef) -> Result<Response<Body>, hyper::Error> {
    error!("Received GS set profile request:\nHeaders:\n{:?}\n\nBody:\n{:?}", req.headers(), req.body());
    todo!()
}
