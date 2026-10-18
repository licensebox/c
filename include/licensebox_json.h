#ifndef LICENSEBOX_JSON_H
#define LICENSEBOX_JSON_H
#include "licensebox.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Small FFI surface over the typed C API. JSON options contain product, keys
 * (id -> public key), version, server and directory only. Identity/clock
 * overrides are trusted callbacks, never JSON options or end-user input.
 * Borrowed callbacks/context must remain alive until lb_client_destroy. */
typedef struct {
  void *context;
  void (*on_sign_in)(void *, const char *, const char *);
  double (*clock)(void *);
  int (*machine_binding)(void *, char *, size_t);
  int (*cancelled)(void *);
} lb_callbacks;
lb_result lb_client_create_json(const char *options_json, const lb_callbacks *,
                                lb_client **output);
/* Operations: lease, require {module}, status, sign_in {timeout}, logout,
 * modules, requests, request {modules:[],note}, access-link,
 * record {command,success,elapsed}. Always returns caller-owned JSON on
 * success, including a JSON string for access-link and null for record/logout.
 * Release output with lb_free. Serialize calls and reading errors together in
 * language bindings. Callbacks must not reenter the client. */
lb_result lb_client_call_json(lb_client *, const char *operation,
                              const char *arguments_json, char **output_json);
lb_result lb_verify_lease_json(const char *token, const char *product,
                               const char *keys_json, double now,
                               char **lease_json);
#ifdef __cplusplus
}
#endif
#endif
