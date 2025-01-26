use rocket::{get, launch, routes, Request};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome};
use rocket_gssapi::oid::{GSS_NT_KRB5_PRINCIPAL, GSS_MECH_KRB5, OidSet};
use rocket_gssapi::name::Name;
use rocket_gssapi::{GssapiFairing, GssapiAuth};

/// This example shows how to chain together the GssapiResponse guard to be used
/// with another request guard, for example interacting with a database.

#[launch]
async fn rocket() -> _ {
    let name = Name::new(
        "HTTP/localhost@LUDD.LTU.SE".as_ref(),
        Some(&GSS_NT_KRB5_PRINCIPAL),
    )
        .expect("Can't decode principal name")
        .canonicalize(Some(&GSS_MECH_KRB5))
        .expect("Can't canonicalize principal name");

    let mut desired_mechs = OidSet::new().expect("Failed to create OIDSet");
    desired_mechs.add(&GSS_MECH_KRB5).expect("Failed to add OID");

    rocket::build()
        .attach(GssapiFairing::new(Some(name), None))
        .mount("/", routes![secure_index])
}

struct User {
    name: String,
    mail: String,
}
#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if let Outcome::Success(g) = req.guard::<GssapiAuth>().await {
            let u = User {
                name: g.source.clone().unwrap().split_once('@').unwrap().0.to_string(),
                mail: g.source.unwrap().to_lowercase(),
            };
            Outcome::Success(u)
        } else {
            Outcome::Forward(Status::Unauthorized)
        }
    }
}

#[get("/")]
async fn secure_index(user: User) -> String {
    format!("Hello {} <{}>!", user.name, user.mail)
}