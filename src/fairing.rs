use crate::guard::GssapiAuth;
use base64::prelude::*;
use libgssapi::context::{SecurityContext, ServerCtx};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::OidSet;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::form::Shareable;
use rocket::http::{Header, Status};
use rocket::{error, info, warn, Data, Orbit, Request, Response, Rocket};
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

type ContextStore = HashMap<String, Arc<Mutex<ServerCtx>>>;
type IdentifierFunction = dyn Fn(&mut Request) -> Option<String> + Send + Sync;

pub struct GssapiFairing {
    name: Option<Name>,
    desired_mechs: Option<OidSet>,
    identifier: Box<IdentifierFunction>,
    // todo: implement method to prune these two
    contexts: Arc<Mutex<ContextStore>>,
    usage: CredUsage,
}
impl GssapiFairing {
    /// Creates a Kerberos fairing, setting up it's use for the GssapiAuth guard
    ///
    /// Takes a GSSAPI name and supported GSSAPI mechanisms as arguments. Set to None to use
    /// system defaults(?)
    pub fn new(name: Option<Name>, desired_mechs: Option<OidSet>, usage: CredUsage) -> GssapiFairing {
        GssapiFairing {
            name,
            desired_mechs,
            identifier: Box::new(|r| r.client_ip().map(|ip| ip.to_string())),
            contexts: Arc::new(Mutex::new(ContextStore::default())),
            usage,
        }
    }

    /// By default, the `Request::client_ip()` result is used to identify clients in order to
    /// work their SecurityContexts to completion. If you instead want to use a different method
    /// to identify clients you can set it here.
    pub fn set_identifier(&mut self, identifier: &'static IdentifierFunction) {
        self.identifier = Box::new(identifier);
    }
}

#[derive(Debug, Clone)]
struct CachedBuf(Vec<u8>);

impl Deref for CachedBuf {
    type Target = CachedBuf;

    fn deref(&self) -> &Self::Target {
        self
    }
}

unsafe impl Shareable for CachedBuf {
    fn size(&self) -> usize {
        self.0.size()
    }
}

#[rocket::async_trait]
impl Fairing for GssapiFairing {
    fn info(&self) -> Info {
        Info {
            name: "Kerberos Authentication",
            kind: Kind::Response | Kind::Request,
        }
    }
    
    /// This function handles the GSSAPI data sent from the client in the `Authorization: Negotiate`
    /// header, parsing it to a format suitable for use for the GssapiAuth request guard.
    ///
    /// When a client initially sends an authorization header, a ServerContext is created to store
    /// the back-and-forth communication of the client and server, which may involve one or more
    /// set of requests and responses. When the context is completed, a GssapiAuth is created
    /// and the context is dropped.
    async fn on_request(&self, req: &mut Request<'_>, _: &mut Data<'_>) {
        if let Some(token) = req
            .headers()
            .get_one("Authorization")
            .unwrap_or_default()
            .strip_prefix("Negotiate ")
        {
            let identifier = &self.identifier;
            let client = if let Some(c) = identifier(&mut req.clone()) {
                c
            } else {
                info!("Kerberos: Failed to identify client");
                return;
            };

            if let Ok(client_tok) = &BASE64_STANDARD.decode(token) {
                let mut ctx_store = if let Ok(c) = self.contexts.lock() {
                    c
                } else {
                    error!("Kerberos: Failed to lock context store");
                    return;
                };

                let mut is_complete = false;
                let mut is_failed = false;
                let buf = if let Some(ctx) = ctx_store.get(&client.to_string()) {
                    // Existing context still present
                    if let Ok(mut ctx) = ctx.try_lock() {
                        let res = match ctx.step(client_tok) {
                            Ok(res) => res,
                            Err(e) => {
                                warn!(
                                    "Kerberos: Failed to work context: {}, client: {}",
                                    e, client
                                );
                                is_failed = true;
                                None
                            }
                        };

                        // Pass the Gssapi data to the request guard
                        if ctx.is_complete() {
                            req.local_cache(|| {
                                let g: GssapiAuth = ctx.into();
                                g
                            });
                            is_complete = true;
                        }
                        res
                    } else {
                        error!("Kerberos: Can't lock context for: {}", client);
                        is_failed = true;
                        None
                    }
                } else {
                    None
                };

                if is_failed {
                    ctx_store.remove(&client.to_string());
                };

                let buf = if buf.is_none() && !is_complete {
                    // Initiate a new context
                    let cred = Cred::acquire(
                        self.name.as_ref(),
                        None,
                        self.usage,
                        self.desired_mechs.as_ref(),
                    );
                    let cred = if let Ok(c) = cred {
                        c
                    } else {
                        error!(
                            "Kerberos: Failed to acquire credentials: {}",
                            cred.unwrap_err()
                        );
                        return;
                    };

                    let mut ctx = ServerCtx::new(Some(cred));

                    let res = match ctx.step(client_tok) {
                        Ok(res) => res,
                        Err(e) => {
                            warn!(
                                "Kerberos: Failed to work context: {}, client: {}",
                                e, client
                            );
                            return;
                        }
                    };

                    if !ctx.is_complete() {
                        // Save the context waiting for the next HTTP request
                        ctx_store.insert(client.to_string(), Arc::new(Mutex::new(ctx)));
                    } else {
                        // Pass the Gssapi data to the request guard
                        req.local_cache(|| GssapiAuth::from(ctx));
                    };
                    res
                } else {
                    None
                };

                if is_complete {
                    // Clean up the old context
                    ctx_store.remove(&client.to_string());
                }

                if let Some(buf) = buf {
                    req.local_cache(|| CachedBuf(buf.to_vec()));
                }
            } else {
                warn!(
                    "Kerberos: Failed to decode Negotiate header: {}, client: {}",
                    token, client
                );
            }
        }
    }

    /// Responses need to have the `www-authenticate: Negotiate` header applied
    /// in order to trigger a GSSAPI negotiation with clients.
    ///
    /// When a client receives that header in a response on a 401 response, they may fetch a
    /// credential and send a client token to the server, which is then handled by the on_request
    /// above.
    ///
    /// If the context is not completed, the server may return a server token back to the client,
    /// which in turn may respond with another client token. This process repeats until the
    /// security context is established, after which the server should send an HTTP code 200 with
    /// the final server token.
    async fn on_response<'r>(&self, req: &'r Request<'_>, res: &mut Response<'r>) {
        match res.status() {
            Status::Unauthorized => {
                let buf = &req.local_cache(|| CachedBuf(Vec::<u8>::new())).0;
                res.set_header(Header::new(
                    "WWW-Authenticate",
                    format!("Negotiate {}", BASE64_STANDARD.encode(buf)),
                ));
            }
            Status::Ok => {
                let buf = &req.local_cache(|| CachedBuf(Vec::<u8>::new())).0;
                if !buf.is_empty() {
                    res.set_header(Header::new(
                        "WWW-Authenticate",
                        format!("Negotiate {}", BASE64_STANDARD.encode(buf)),
                    ));
                }
            }
            _ => {}
        }
    }
}
