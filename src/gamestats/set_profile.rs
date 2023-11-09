use crate::backend::backends::BackendsRef;
use hyper::{Body, Request, Response};
use log::error;

pub(crate) async fn gs_set_profile(
    req: Request<Body>,
    _backends: BackendsRef,
) -> Result<Response<Body>, hyper::Error> {
    error!(
        "Received GS set profile request:\nHeaders:\n{:?}\n\nBody:\n{:?}",
        req.headers(),
        req.body()
    );
    todo!()
}
