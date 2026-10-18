#include "licensebox_json.h"
#include <stdio.h>
#include <stdlib.h>
#define CHECK(test)                                                            \
  do {                                                                         \
    if (!(test)) {                                                             \
      fprintf(stderr, "JSON ABI check failed at line %d\n", __LINE__);         \
      return 1;                                                                \
    }                                                                          \
  } while (0)
int main(void) {
  lb_client *c = NULL;
  char *out = NULL;
  const char *invalid[] = {
      "",
      "[]",
      "{\"product\":\"demo\",\"keys\":{},\"ca_bundle\":\"\"}",
      "null",
      "{} trailing",
      "{\"product\":\"demo\",\"keys\":{},\"machine_binding\":\"fake\"}",
      "{\"product\":\"demo\\u0000other\",\"keys\":{}}",
      "{\"product\":\"demo\",\"keys\":[],\"clock\":0}"};
  for (size_t i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
    CHECK(lb_client_create_json(invalid[i], NULL, &c) == LB_INVALID_ARGUMENT);
    CHECK(c == NULL);
  }
  CHECK(lb_client_create_json("{\"product\":\"demo\",\"keys\":{\"test\":"
                              "\"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg\"}"
                              ",\"server\":\"http://127.0.0.1:1\"}",
                              NULL, &c) == LB_OK);
  CHECK(lb_client_set_ca_bundle(c, "") == LB_INVALID_ARGUMENT);
  CHECK(lb_client_set_ca_bundle(c, "/synthetic/ca.pem") == LB_OK);
  CHECK(lb_client_set_ca_bundle(c, NULL) == LB_OK);
  const char *operations[] = {"lease",   "require", "request", "record",
                              "sign_in", "sign_in", "unknown"};
  const char *args[] = {
      "null",
      "{\"module\":123}",
      "{\"modules\":\"export\"}",
      "{\"command\":\"export\",\"success\":\"yes\",\"elapsed\":0}",
      "{\"timeout\":-1}",
      "{\"timeout\":\"3\"}",
      "{}"};
  for (size_t i = 0; i < sizeof(operations) / sizeof(*operations); i++) {
    CHECK(lb_client_call_json(c, operations[i], args[i], &out) ==
          LB_INVALID_ARGUMENT);
    CHECK(out == NULL);
  }
  const char *heartbeat_args[] = {"{}", "{\"module\":\"\"}",
                                   "{\"module\":true}",
                                   "{\"module\":\"core\\u0000other\"}"};
  for (size_t i = 0; i < sizeof(heartbeat_args)/sizeof(*heartbeat_args); i++) {
    CHECK(lb_client_call_json(c, "heartbeat", heartbeat_args[i], &out) == LB_INVALID_ARGUMENT);
    CHECK(out == NULL);
  }
  CHECK(lb_heartbeat(c, "", &out) == LB_INVALID_ARGUMENT);
  CHECK(out == NULL);
  lb_client_destroy(c);
  puts("PASS: malformed FFI inputs and identity override options rejected "
       "before network access");
  return 0;
}
