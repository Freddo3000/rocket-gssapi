# rocket-gssapi

A simple fairing to Rocket implementing GSSAPI authentication using [libgssapi](https://crates.io/crates/libgssapi).

See [RFC 4559](https://www.rfc-editor.org/rfc/rfc4559) for details on how SPNEGO HTTP Authentication works, which this
library tries to implement as closely as possible.

### Example usage
```rust
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
        .attach(GssapiFairing::new(Some(name), Some(desired_mechs)))
        .mount("/", routes![secure_index])
}

#[get("/")]
async fn secure_index(gss: GssapiAuth) -> String {
    format!("Hello {:?}!", gss.source.unwrap())
}
```

### Notes, tips
* This library is fairly untested as, well, Kerberos isn't all that easy to work with. I've got it working with
  Firefox, as well as `curl --negotiate`.
* In my Kerberos setup, setting `desired_mechs` caused Kerberos to fail with `GSS_S_BAD_MECH` errors. Setting it to
  `None` and letting it figure it out by itself resolved the issue.
* Setting `KRB5_KTNAME=http.keytab` and `KRB5_TRACE=/dev/stderr` may make it easier to debug Kerberos issues.

---

This repository is primarily hosted on the [Luleå Academic Computer Society /LUDD/](https://git.ludd.ltu.se/freddo/rocket-gssapi)
gitlab server.