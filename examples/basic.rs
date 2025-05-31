use libgssapi::credential::CredUsage;
use rocket::{get, launch, routes};
use rocket_gssapi::oid::{GSS_NT_KRB5_PRINCIPAL, GSS_MECH_KRB5, OidSet};
use rocket_gssapi::name::Name;
use rocket_gssapi::{GssapiFairing, GssapiAuth};

#[launch]
async fn rocket() -> _ {
    let name = Name::new(
        "HTTP/example@example.com".as_ref(),
        Some(&GSS_NT_KRB5_PRINCIPAL),
    )
        .expect("Can't decode principal name")
        .canonicalize(Some(&GSS_MECH_KRB5))
        .expect("Can't canonicalize principal name");

    let mut desired_mechs = OidSet::new().expect("Failed to create OIDSet");
    desired_mechs.add(&GSS_MECH_KRB5).expect("Failed to add OID");

    rocket::build()
        .attach(GssapiFairing::new(Some(name), None, CredUsage::Accept))
        .mount("/", routes![secure_index])
}

#[get("/")]
async fn secure_index(gss: GssapiAuth) -> String {
    format!("Hello {:?}!", gss.source.unwrap())
}