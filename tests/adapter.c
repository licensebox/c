/* Synthetic host and clock overrides belong only to this conformance adapter.
 */
#include "licensebox.h"
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static struct json_object *get(struct json_object *o, const char *k) {
  struct json_object *v = NULL;
  json_object_object_get_ex(o, k, &v);
  return v;
}
static const char *s(struct json_object *o, const char *k) {
  const char *v = json_object_get_string(get(o, k));
  return v ? v : "";
}
static double clock_fn(void *p) {
  return json_object_get_double(get(p, "now"));
}
static int binding_fn(void *p, char *out, size_t size) {
  return snprintf(out, size, "%s", s(p, "binding")) >= (int)size;
}
static void signin(void *p, const char *url, const char *code) {
  (void)p;
  (void)url;
  (void)code;
}
int main(void) {
  char *input = calloc((1u << 20) + 1, 1);
  if (!input)
    return 2;
  size_t n = fread(input, 1, 1u << 20, stdin);
  input[n] = 0;
  struct json_object *o = json_tokener_parse(input);
  free(input);
  if (!o)
    return 2;
  const char *op = s(o, "op");
  lb_public_key keys[64];
  size_t key_count = 0;
  struct json_object *key_object = get(o, "keys");
  if (key_object) {
    json_object_object_foreach(key_object, k, v) {
      if (key_count >= 64)
        return 2;
      keys[key_count++] = (lb_public_key){k, json_object_get_string(v)};
    }
  }
  lb_result r = LB_OK;
  char *output = NULL;
  lb_client *client = NULL;
  int string_output = 0;
  if (!strcmp(op, "derive") || !strcmp(op, "native")) {
    char binding[128];
    r = !strcmp(op, "native")
            ? lb_native_binding(s(o, "product"), binding, sizeof(binding))
            : lb_derive_binding(s(o, "product"), s(o, "source"), s(o, "raw_id"),
                                binding, sizeof(binding));
    if (r == LB_OK)
      output = strdup(binding);
    string_output = 1;
  } else if (!strcmp(op, "verify"))
    r = lb_verify_lease(s(o, "token"), s(o, "product"), keys, key_count,
                        clock_fn(o), &output);
  else {
    lb_config cfg = {.product = s(o, "product"),
                     .keys = keys,
                     .key_count = key_count,
                     .server = s(o, "server"),
                     .directory = s(o, "directory"),
                     .version = "conformance",
                     .context = o,
                     .clock = clock_fn,
                     .on_sign_in = signin,
                     .machine_binding = get(o, "binding") ? binding_fn : NULL};
    r = lb_client_create(&cfg, &client);
    if (r == LB_OK) {
      if (!strcmp(op, "lease"))
        r = lb_lease(client, &output);
      else if (!strcmp(op, "require"))
        r = lb_require(client, *s(o, "module") ? s(o, "module") : "core",
                       &output);
      else if (!strcmp(op, "repeat")) {
        r = lb_require(client, "core", &output);
        lb_free(output);
        output = NULL;
        if (r == LB_OK)
          r = lb_require(client, "core", &output);
      } else if (!strcmp(op, "status"))
        r = lb_status(client, &output);
      else if (!strcmp(op, "sign_in"))
        r = lb_sign_in(client, 3, &output);
      else if (!strcmp(op, "logout"))
        r = lb_logout(client);
      else if (!strcmp(op, "modules"))
        r = lb_modules(client, &output);
      else if (!strcmp(op, "requests"))
        r = lb_requests(client, &output);
      else if (!strcmp(op, "access-link")) {
        r = lb_access_link(client, &output);
        string_output = 1;
      } else if (!strcmp(op, "request")) {
        const char *modules[] = {"export"};
        r = lb_request_access(client, modules, 1, "café – test", &output);
      } else if (!strcmp(op, "record")) {
        r = lb_record(client, "export", 1, .125);
        if (r == LB_OK)
          r = lb_record(client, "export", 0, .025);
      } else
        r = LB_INVALID_ARGUMENT;
    }
  }
  struct json_object *answer = json_object_new_object();
  json_object_object_add(answer, "ok", json_object_new_boolean(r == LB_OK));
  if (r != LB_OK)
    json_object_object_add(
        answer, "error",
        json_object_new_string(client && strcmp(lb_error_code(client), "ok")
                                   ? lb_error_code(client)
                                   : lb_result_code(r)));
  else
    json_object_object_add(answer, "value",
                           output
                               ? (string_output ? json_object_new_string(output)
                                                : json_tokener_parse(output))
                               : NULL);
  puts(json_object_to_json_string_ext(answer, JSON_C_TO_STRING_PLAIN));
  lb_free(output);
  lb_client_destroy(client);
  json_object_put(o);
  json_object_put(answer);
  return 0;
}
