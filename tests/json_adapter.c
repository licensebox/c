/* Synthetic test driver for the public JSON/FFI API. */
#include "licensebox_json.h"
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct json_object J;
static J *get(J *o, const char *k) {
  J *v = NULL;
  json_object_object_get_ex(o, k, &v);
  return v;
}
static const char *s(J *o, const char *k) {
  const char *v = json_object_get_string(get(o, k));
  return v ? v : "";
}
static const char *json(J *o) {
  return json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN);
}
static double clock_fn(void *p) {
  return json_object_get_double(get(p, "now"));
}
static int binding_fn(void *p, char *out, size_t n) {
  return snprintf(out, n, "%s", s(p, "binding")) >= (int)n;
}
static void signin(void *p, const char *u, const char *c) {
  (void)p;
  (void)u;
  (void)c;
}
int main(void) {
  char *text = calloc((1u << 20) + 1, 1);
  if (!text)
    return 2;
  size_t n = fread(text, 1, 1u << 20, stdin);
  text[n] = 0;
  J *o = json_tokener_parse(text);
  free(text);
  if (!o)
    return 2;
  const char *op = s(o, "op");
  char *out = NULL;
  lb_client *c = NULL;
  lb_result r = LB_OK;
  if (!strcmp(op, "derive") || !strcmp(op, "native")) {
    char buf[128];
    r = !strcmp(op, "native")
            ? lb_native_binding(s(o, "product"), buf, sizeof(buf))
            : lb_derive_binding(s(o, "product"), s(o, "source"), s(o, "raw_id"),
                                buf, sizeof(buf));
    if (r == LB_OK) {
      J *v = json_object_new_string(buf);
      out = strdup(json(v));
      json_object_put(v);
    }
  } else if (!strcmp(op, "verify"))
    r = lb_verify_lease_json(s(o, "token"), s(o, "product"),
                             json(get(o, "keys")), clock_fn(o), &out);
  else {
    J *options = json_object_new_object();
    const char *fields[] = {"product", "keys", "server", "directory"};
    for (size_t i = 0; i < 4; i++)
      json_object_object_add(options, fields[i],
                             json_object_get(get(o, fields[i])));
    if (get(o, "ca_bundle"))
      json_object_object_add(options, "ca_bundle",
                             json_object_get(get(o, "ca_bundle")));
    json_object_object_add(options, "version",
                           json_object_new_string("conformance"));
    lb_callbacks cb = {.context = o,
                       .clock = clock_fn,
                       .machine_binding = get(o, "binding") ? binding_fn : NULL,
                       .on_sign_in = signin};
    r = lb_client_create_json(json(options), &cb, &c);
    json_object_put(options);
    if (r == LB_OK) {
      const char *operation = op;
      J *args = json_object_new_object();
      if (!strcmp(op, "require") || !strcmp(op, "repeat") ||
          !strcmp(op, "heartbeat") || !strcmp(op, "heartbeat-repeat") ||
          !strcmp(op, "heartbeat-after-require")) {
        operation = !strncmp(op, "heartbeat", 9) ? "heartbeat" : "require";
        json_object_object_add(
            args, "module",
            json_object_new_string(*s(o, "module") ? s(o, "module") : "core"));
      } else if (!strcmp(op, "request")) {
        J *a = json_object_new_array();
        json_object_array_add(a, json_object_new_string("export"));
        json_object_object_add(args, "modules", a);
        json_object_object_add(args, "note",
                               json_object_new_string("café – test"));
      } else if (!strcmp(op, "sign_in"))
        json_object_object_add(args, "timeout", json_object_new_int(3));
      else if (!strcmp(op, "record")) {
        json_object_object_add(args, "command",
                               json_object_new_string("export"));
        json_object_object_add(args, "success", json_object_new_boolean(1));
        json_object_object_add(args, "elapsed", json_object_new_double(.125));
      }
      if (!strcmp(op, "heartbeat-after-require")) {
        r = lb_client_call_json(c, "require", json(args), &out);
        lb_free(out); out = NULL;
      }
      if (r == LB_OK)
        r = lb_client_call_json(c, operation, json(args), &out);
      if (r == LB_OK && (!strcmp(op, "repeat") || !strcmp(op, "heartbeat-repeat") || !strcmp(op, "record"))) {
        lb_free(out);
        out = NULL;
        if (!strcmp(op, "record")) {
          json_object_object_add(args, "success", json_object_new_boolean(0));
          json_object_object_add(args, "elapsed", json_object_new_double(.025));
        }
        r = lb_client_call_json(c, operation, json(args), &out);
      }
      json_object_put(args);
    }
  }
  J *answer = json_object_new_object();
  json_object_object_add(answer, "ok", json_object_new_boolean(r == LB_OK));
  if (r != LB_OK)
    json_object_object_add(
        answer, "error",
        json_object_new_string(c && strcmp(lb_error_code(c), "ok")
                                   ? lb_error_code(c)
                                   : lb_result_code(r)));
  else
    json_object_object_add(answer, "value",
                           out ? json_tokener_parse(out) : NULL);
  puts(json(answer));
  lb_free(out);
  lb_client_destroy(c);
  json_object_put(o);
  json_object_put(answer);
  return 0;
}
