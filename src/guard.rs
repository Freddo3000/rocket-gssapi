use libgssapi::context::{SecurityContext, ServerCtx};
use rocket::Request;
use std::ops::Deref;
use std::sync::MutexGuard;
use rocket::form::Shareable;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome};


#[derive(Debug, Default, Clone)]
pub struct GssapiAuth {
    pub target: Option<String>,
    pub source: Option<String>,
    pub lifetime: Option<f32>,
    pub complete: bool,
}
impl Deref for GssapiAuth {
    type Target = bool;

    fn deref(&self) -> &Self::Target {
        &self.complete
    }
}

unsafe impl Shareable for GssapiAuth {
    fn size(&self) -> usize {
        size_of_val(self)
    }
}
impl From<ServerCtx> for GssapiAuth {

    fn from(mut ctx: ServerCtx) -> GssapiAuth {
        GssapiAuth {
            target: ctx.target_name()
                .map_or(None, |t| Some(t.to_string())),
            source: ctx.source_name()
                .map_or(None, |t| Some(t.to_string())),
            lifetime: ctx.lifetime().map_or(None, |l| Some(l.as_secs_f32())),
            complete: ctx.is_complete()

        }
    }
}
impl From<MutexGuard<'_, ServerCtx>> for GssapiAuth {

    fn from(mut ctx: MutexGuard<ServerCtx>) -> GssapiAuth {
        GssapiAuth {
            target: ctx.target_name()
                .map_or(None, |t| Some(t.to_string())),
            source: ctx.source_name()
                .map_or(None, |t| Some(t.to_string())),
            lifetime: ctx.lifetime().map_or(None, |l| Some(l.as_secs_f32())),
            complete: ctx.is_complete()

        }
    }
}
#[rocket::async_trait]
impl<'r> FromRequest<'r> for GssapiAuth {
    type Error = std::convert::Infallible;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let g: &GssapiAuth = req.local_cache(GssapiAuth::default);
        if g.complete {
            Outcome::Success(g.clone())
        } else {
            Outcome::Forward(Status::Unauthorized)
        }
    }
}