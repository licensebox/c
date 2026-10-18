#ifndef LICENSEBOX_H
#define LICENSEBOX_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct lb_client lb_client;
typedef enum {
  LB_OK = 0,
  LB_MALFORMED,
  LB_VERSION,
  LB_UNKNOWN_KEY,
  LB_BAD_SIGNATURE,
  LB_EXPIRED,
  LB_IDENTITY_UNAVAILABLE,
  LB_MACHINE_CHANGED,
  LB_SEAT_TRANSFERRED,
  LB_LOCATION_DENIED,
  LB_LOCATION_UNKNOWN,
  LB_REVOKED,
  LB_DENIED,
  LB_SIGN_IN_EXPIRED,
  LB_OFFLINE,
  LB_MODULE_DENIED,
  LB_NOT_SIGNED_IN,
  LB_IO_ERROR,
  LB_HTTP_ERROR,
  LB_PROTOCOL_ERROR,
  LB_NETWORK_ERROR,
  LB_CANCELLED,
  LB_INVALID_ARGUMENT
} lb_result;
typedef struct {
  const char *id;
  const char *public_key;
} lb_public_key;
typedef struct {
  const char *product;
  const lb_public_key *keys;
  size_t key_count;
  const char *version; /* optional */
  const char
      *server; /* default https://licensebox.dev; HTTP only on loopback */
  const char *directory; /* default $XDG_CONFIG_HOME/licensebox/<product> */
  void *context;         /* borrowed; must outlive the client */
  void (*on_sign_in)(void *, const char *url, const char *user_code);
  double (*clock)(void *); /* Unix seconds; NULL uses the system clock */
  /* Platform/test seam. Never supply a binding from an end user. */
  int (*machine_binding)(void *, char *output, size_t capacity);
  int (*cancelled)(void *);
} lb_config;

/* Client operations are serialized. Callbacks must not reenter the client.
 * Output strings belong to the caller and must be released with lb_free.
 * JSON outputs use the public protocol types; no JSON dependency in this
 * header. */
lb_result lb_client_create(const lb_config *, lb_client **output);
void lb_client_destroy(lb_client *);
/* Optional CA certificate PEM file. Set before protected use. NULL restores
 * libcurl defaults; peer and hostname verification are always enabled. */
lb_result lb_client_set_ca_bundle(lb_client *, const char *path);
const char *lb_error_code(const lb_client *);
const char *lb_error_message(const lb_client *);
const char *lb_result_code(lb_result);
void lb_free(void *);
lb_result lb_lease(lb_client *, char **lease_json);
lb_result lb_require(lb_client *, const char *module, char **lease_json);
/* Explicit checkpoint: always signed renew (3s), no activation/key rotation.
 * Requires a nonempty module and saved verified identity. Returns JSON
 * {"lease":<verified lease>,"online":true|false}; offline only before expires.
 * Consumer owns scheduling/cancellation; no background thread is started. */
lb_result lb_heartbeat(lb_client *, const char *module, char **heartbeat_json);
lb_result lb_status(lb_client *, char **lease_json); /* local only */
lb_result lb_sign_in(lb_client *, double timeout_seconds, char **lease_json);
lb_result lb_logout(lb_client *); /* installation key is retained */
lb_result lb_modules(lb_client *, char **modules_json);
lb_result lb_request_access(lb_client *, const char *const *modules,
                            size_t count, const char *note,
                            char **request_json);
lb_result lb_requests(lb_client *, char **requests_json);
lb_result lb_access_link(lb_client *, char **url);
lb_result lb_record(lb_client *, const char *command, int success,
                    double elapsed_seconds);

/* Stateless wire primitives; no private native identifier is logged or saved.
 */
lb_result lb_derive_binding(const char *product, const char *source,
                            const char *raw_id, char *output, size_t capacity);
lb_result lb_native_binding(const char *product, char *output, size_t capacity);
lb_result lb_verify_lease(const char *token, const char *product,
                          const lb_public_key *keys, size_t key_count,
                          double now, char **lease_json);
#ifdef __cplusplus
}
#endif
#endif
