/* Public JSON/FFI convenience API; all licensing behavior remains in the core.
 */
#include "licensebox_json.h"
#include <ctype.h>
#include <json-c/json.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
typedef struct json_object J;
#define JSON_LIMIT (1u << 20)
static J *get(J *o, const char *key) {
  J *value = NULL;
  if (o)
    json_object_object_get_ex(o, key, &value);
  return value;
}
static const char *str(J *o) {
  if (!o || json_object_get_type(o) != json_type_string)
    return NULL;
  const char *value = json_object_get_string(o);
  return value && strlen(value) == (size_t)json_object_get_string_len(o) ? value
                                                                         : NULL;
}
static J *object(const char *text) {
  if (!text || strlen(text) >= JSON_LIMIT)
    return NULL;
  struct json_tokener *tok = json_tokener_new();
  if (!tok)
    return NULL;
  size_t size = strlen(text);
  J *o = json_tokener_parse_ex(tok, text, (int)size);
  size_t end = json_tokener_get_parse_end(tok);
  while (end < size && isspace((unsigned char)text[end]))
    end++;
  int valid = json_tokener_get_error(tok) == json_tokener_success &&
              end == size && o && json_object_get_type(o) == json_type_object;
  json_tokener_free(tok);
  if (!valid) {
    json_object_put(o);
    return NULL;
  }
  return o;
}
static int keys(J *o, lb_public_key *output, size_t *count) {
  *count = 0;
  if (!o || json_object_get_type(o) != json_type_object ||
      json_object_object_length(o) > 64)
    return 0;
  json_object_object_foreach(o, key, value) {
    const char *pub = str(value);
    if (!*key || !pub)
      return 0;
    output[(*count)++] = (lb_public_key){key, pub};
  }
  return 1;
}
lb_result lb_client_create_json(const char *options, const lb_callbacks *cb,
                                lb_client **out) {
  if (!out)
    return LB_INVALID_ARGUMENT;
  *out = NULL;
  J *o = object(options);
  if (!o)
    return LB_INVALID_ARGUMENT;
  lb_public_key public_keys[64];
  size_t n = 0;
  int valid = keys(get(o, "keys"), public_keys, &n);
  json_object_object_foreach(o, key, value) {
    if (!strcmp(key, "keys"))
      continue;
    if ((strcmp(key, "product") && strcmp(key, "version") &&
         strcmp(key, "server") && strcmp(key, "directory") &&
         strcmp(key, "ca_bundle")) ||
        !str(value))
      valid = 0;
  }
  lb_result result = LB_INVALID_ARGUMENT;
  if (valid) {
    lb_config cfg = {.product = str(get(o, "product")),
                     .keys = public_keys,
                     .key_count = n,
                     .version = str(get(o, "version")),
                     .server = str(get(o, "server")),
                     .directory = str(get(o, "directory"))};
    if (cb) {
      cfg.context = cb->context;
      cfg.on_sign_in = cb->on_sign_in;
      cfg.clock = cb->clock;
      cfg.machine_binding = cb->machine_binding;
      cfg.cancelled = cb->cancelled;
    }
    result = lb_client_create(&cfg, out);
    if (result == LB_OK && get(o, "ca_bundle")) {
      result = lb_client_set_ca_bundle(*out, str(get(o, "ca_bundle")));
      if (result != LB_OK) {
        lb_client_destroy(*out);
        *out = NULL;
      }
    }
  }
  json_object_put(o);
  return result;
}
lb_result lb_verify_lease_json(const char *token, const char *product,
                               const char *public_keys_json, double now,
                               char **out) {
  if (!out)
    return LB_INVALID_ARGUMENT;
  *out = NULL;
  J *o = object(public_keys_json);
  lb_public_key public_keys[64];
  size_t n = 0;
  lb_result r = keys(o, public_keys, &n)
                    ? lb_verify_lease(token, product, public_keys, n, now, out)
                    : LB_INVALID_ARGUMENT;
  json_object_put(o);
  return r;
}
lb_result lb_client_call_json(lb_client *c, const char *op,
                              const char *arguments, char **out) {
  if (!c || !op || !out)
    return LB_INVALID_ARGUMENT;
  *out = NULL;
  J *o = object(arguments ? arguments : "{}");
  if (!o)
    return LB_INVALID_ARGUMENT;
  lb_result r = LB_INVALID_ARGUMENT;
  if (!strcmp(op, "lease"))
    r = lb_lease(c, out);
  else if (!strcmp(op, "status"))
    r = lb_status(c, out);
  else if (!strcmp(op, "require") && str(get(o, "module")))
    r = lb_require(c, str(get(o, "module")), out);
  else if (!strcmp(op, "heartbeat") && str(get(o, "module")) &&
           *str(get(o, "module")))
    r = lb_heartbeat(c, str(get(o, "module")), out);
  else if (!strcmp(op, "sign_in")) {
    J *timeout = get(o, "timeout");
    if (!timeout || json_object_get_type(timeout) == json_type_double ||
        json_object_get_type(timeout) == json_type_int) {
      double seconds = json_object_get_double(timeout);
      if (isfinite(seconds) && seconds >= 0)
        r = lb_sign_in(c, seconds, out);
    }
  } else if (!strcmp(op, "logout"))
    r = lb_logout(c);
  else if (!strcmp(op, "modules"))
    r = lb_modules(c, out);
  else if (!strcmp(op, "requests"))
    r = lb_requests(c, out);
  else if (!strcmp(op, "access-link")) {
    char *link = NULL;
    r = lb_access_link(c, &link);
    if (r == LB_OK) {
      J *value = json_object_new_string(link);
      *out = value ? strdup(json_object_to_json_string_ext(
                         value, JSON_C_TO_STRING_PLAIN))
                   : NULL;
      json_object_put(value);
      if (!*out)
        r = LB_IO_ERROR;
    }
    lb_free(link);
  } else if (!strcmp(op, "request")) {
    J *a = get(o, "modules"), *note = get(o, "note");
    if (a && json_object_get_type(a) == json_type_array &&
        (!note || str(note))) {
      size_t n = json_object_array_length(a);
      if (n > 0 && n <= 1024) {
        const char **names = calloc(n, sizeof(*names));
        if (!names)
          r = LB_IO_ERROR;
        else {
          int valid = 1;
          for (size_t i = 0; i < n; i++) {
            names[i] = str(json_object_array_get_idx(a, i));
            if (!names[i])
              valid = 0;
          }
          if (valid)
            r = lb_request_access(c, names, n, note ? str(note) : "", out);
          free(names);
        }
      }
    }
  } else if (!strcmp(op, "record")) {
    J *success = get(o, "success"), *elapsed = get(o, "elapsed");
    if (str(get(o, "command")) && success &&
        json_object_get_type(success) == json_type_boolean && elapsed &&
        (json_object_get_type(elapsed) == json_type_double ||
         json_object_get_type(elapsed) == json_type_int))
      r = lb_record(c, str(get(o, "command")), json_object_get_boolean(success),
                    json_object_get_double(elapsed));
  }
  json_object_put(o);
  if (r == LB_OK && !*out) {
    *out = strdup("null");
    if (!*out)
      r = LB_IO_ERROR;
  }
  return r;
}
