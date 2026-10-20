# Licensebox for C

Native application licensing: email sign-in, signed machine-bound leases,
three-second silent renewal and verified offline access. Linux is the supported
and runtime-validated platform for this first release. Other OS adapters are
pending; no random machine identifier is used as a fallback.

Dependencies: C11, CMake 3.20+, OpenSSL 3.5+ (the first with ML-DSA), libcurl
7.85+, json-c and pthreads. Ubuntu 26.04, Debian 13 and Fedora 42 ship OpenSSL
3.5; on older systems build against a newer OpenSSL (`-DOPENSSL_ROOT_DIR=...`).
For an Ubuntu development environment:

```sh
sudo apt-get install libssl-dev libcurl4-openssl-dev libjson-c-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build --prefix /your/install/prefix
```

Consumers use `find_package(licensebox CONFIG REQUIRED)` and link
`licensebox::c`. Static and shared builds are supported (`BUILD_SHARED_LIBS`).

For language bindings, build with `-DBUILD_SHARED_LIBS=ON`. Version 0.2.0 adds
`licensebox_json.h`: a small JSON interface over the same client operations,
plus borrowed callbacks for sign-in, cancellation and trusted platform/test
integration. Config JSON never accepts machine-identity or clock overrides.
Bindings must retain callbacks until client destruction and serialize an
operation with reading its error. All successful outputs are JSON strings owned
by the caller, released with `lb_free`; `access-link` returns a JSON string value.
The original typed C API and ABI remain available. Version 0.3.0 adds the optional
`ca_bundle` JSON configuration field and `lb_client_set_ca_bundle` for an
explicit CA certificate PEM file. Use this when the linked TLS library lacks a
default trust store. Peer and hostname verification remain enabled; passing
`NULL` to the setter restores the library default.

```c
#include <licensebox.h>
#include <stdio.h>

int run_export(void) {
    lb_public_key keys[] = {{"myapp-k1", "YOUR_PUBLIC_VERIFICATION_KEY"}};
    lb_config config = {.product="myapp", .keys=keys, .key_count=1, .version="1.0"};
    lb_client *client = NULL;
    lb_result result = lb_client_create(&config, &client);
    if (result != LB_OK) return 1;
    char *lease_json = NULL;
    result = lb_require(client, "export", &lease_json);
    if (result != LB_OK) fprintf(stderr, "%s\n", lb_error_message(client));
    lb_free(lease_json);
    lb_client_destroy(client);
    if (result != LB_OK) return 1;
    /* Read/process user files only after authorization succeeds. */
    return 0;
}
```

Keep one client for the application's lifetime; the small example illustrates
ownership. All returned strings belong to the caller (`lb_free`), including JSON
lease/module/request results and access-link URLs. The public header has no JSON
library dependency. Functions return `lb_result`; use `lb_error_code` and
`lb_error_message` for server detail. Check every result before protected work.
Client calls serialize internally. Callbacks must not reenter the client.

`lb_lease`, `lb_status` (local only), `lb_sign_in`, `lb_logout`, `lb_modules`,
`lb_request_access`, `lb_requests`, `lb_access_link` and `lb_record` cover the
remaining client operations. `lb_config.on_sign_in` displays/opens sign-in URLs;
`cancelled` supports interruption. Config strings/keys are copied at creation;
callback context is borrowed. `machine_binding`/`clock` are trusted platform/test
seams, never user-supplied identity overrides. The default private credential
folder is compatible with other Licensebox SDKs.

Machine/seat/location refusals stop access and persist offline. `LB_OFFLINE`
means an expired lease could not renew; `LB_MODULE_DENIED` means missing access;
`LB_REVOKED` removes cached access state. No background work starts automatically.
Raw native IDs remain local. Software recognition is not hardware attestation;
cloned/spoofed IDs or modified host software remain limitations. Any payments or
billing are handled separately by product administrators.

The [shared contract](https://github.com/licensebox/protocol) tests this client
against the same scenarios as Go, Python and TypeScript. Crypto uses OpenSSL's
[Ed25519](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ED25519/) and
[ML-DSA-65](https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/).

Version 0.5.0 speaks protocol v3: every licence and request is signed with
Ed25519 and ML-DSA-65 together, and both must verify. Trusted keys are written
`ed25519-mldsa65:<base64url>`, about 2.7 KB, so keep them in a file or constant.
Administration stays in the [Go CLI](https://github.com/licensebox/go).

MIT. Copyright © 2026 [Vijai Kumar](https://meshing.engineer).

Version 0.4.0 adds the explicit heartbeat API and optional signed contact policy.

## Optional protected-work checkpoints

`lb_heartbeat(client, "export", &json)` always attempts a signed renewal with a
three-second network bound, even after `lb_require` succeeded on the same
client. It returns caller-owned JSON `{"lease":{...},"online":true|false}`.
A verified unexpired saved lease may authorize offline work with `online=false`;
its signed `expires` is never extended by a failed check. Missing state returns
`not_signed_in`; invalid state, missing modules and explicit policy refusals fail
closed. Heartbeat never opens sign-in, creates/rotates a key or transfers seats.

```c
/* Invoke from the application's own event loop or batch checkpoint. */
int checkpoint(lb_client *client) {
    char *state = NULL;
    lb_result result = lb_heartbeat(client, "export", &state);
    lb_free(state);
    return result == LB_OK; /* caller pauses protected work safely on failure */
}
```

The optional signed lease `heartbeat` object contains integer `interval_seconds`
and `grace_seconds`. Missing/null means legacy scheduling; valid enabled policy
is checked when verifying every lease. Consumers choose scheduling and safe
shutdown. Use the server interval when present; independently stop protected work
at the last verified expiry even if renewal is slow. No failed check may move
that deadline. This SDK starts no worker thread and never exits the application;
callbacks retain their existing thread and non-reentry requirements. The JSON
ABI exposes `heartbeat` with `{"module":"export"}` and the same result/lifetime.
