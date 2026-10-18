#define _GNU_SOURCE
#include "licensebox.h"
#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <math.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define LIMIT (1u << 20)
#define BINDING_CAP 128
typedef struct json_object J;
struct lb_client {
  char *product, *version, *server, *directory, *ca_bundle;
  lb_public_key *keys;
  size_t key_count;
  lb_config callbacks;
  char binding[BINDING_CAP];
  J *checked;
  pthread_mutex_t mutex;
  long status;
  lb_result result;
  char code[80], detail[512];
};
static const char *codes[] = {"ok",
                              "malformed",
                              "version",
                              "unknown_key",
                              "bad_signature",
                              "expired",
                              "identity_unavailable",
                              "machine_changed",
                              "seat_transferred",
                              "location_denied",
                              "location_unknown",
                              "revoked",
                              "denied",
                              "sign_in_expired",
                              "offline",
                              "module_denied",
                              "not_signed_in",
                              "io_error",
                              "http_error",
                              "protocol_error",
                              "network_error",
                              "cancelled",
                              "invalid_argument"};
const char *lb_result_code(lb_result r) {
  return r >= LB_OK && r <= LB_INVALID_ARGUMENT ? codes[r] : "unknown_error";
}
const char *lb_error_code(const lb_client *c) {
  return c ? c->code : "invalid_argument";
}
const char *lb_error_message(const lb_client *c) {
  return c ? c->detail : "invalid client";
}
void lb_free(void *p) { free(p); }
static lb_result fail(lb_client *c, lb_result r, const char *code,
                      const char *detail) {
  c->result = r;
  snprintf(c->code, sizeof(c->code), "%s", code ? code : lb_result_code(r));
  snprintf(c->detail, sizeof(c->detail), "%s", detail ? detail : c->code);
  return r;
}
static J *get(J *o, const char *key) {
  J *v = NULL;
  if (o)
    json_object_object_get_ex(o, key, &v);
  return v;
}
static const char *str(J *o) {
  const char *s = o ? json_object_get_string(o) : NULL;
  return s ? s : "";
}
static const char *field(J *o, const char *key) { return str(get(o, key)); }
static void add(J *o, const char *key, const char *value) {
  json_object_object_add(o, key, json_object_new_string(value ? value : ""));
}
static const char *json(J *o) {
  return json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN |
                                               JSON_C_TO_STRING_NOSLASHESCAPE);
}
static char *format(const char *f, ...) {
  va_list a;
  va_start(a, f);
  char *s = NULL;
  if (vasprintf(&s, f, a) < 0)
    s = NULL;
  va_end(a);
  return s;
}
static J *parse(const char *text) {
  if (!text || strlen(text) > LIMIT)
    return NULL;
  struct json_tokener *t = json_tokener_new();
  if (!t)
    return NULL;
  json_tokener_set_flags(t, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
  J *o = json_tokener_parse_ex(t, text, (int)strlen(text) + 1);
  if (json_tokener_get_error(t) != json_tokener_success) {
    json_object_put(o);
    o = NULL;
  }
  json_tokener_free(t);
  return o;
}
static char *enc(const unsigned char *bytes, size_t size) {
  if (size > LIMIT)
    return NULL;
  char *s = malloc(4 * ((size + 2) / 3) + 1);
  if (!s)
    return NULL;
  int n = EVP_EncodeBlock((unsigned char *)s, bytes, (int)size);
  for (int i = 0; i < n; i++) {
    if (s[i] == '+')
      s[i] = '-';
    else if (s[i] == '/')
      s[i] = '_';
  }
  while (n > 0 && s[n - 1] == '=')
    s[--n] = 0;
  return s;
}
static unsigned char *dec(const char *text, size_t *length) {
  if (!text)
    return NULL;
  size_t n = strlen(text);
  if (!n || n > LIMIT || n % 4 == 1)
    return NULL;
  size_t padded = (n + 3) / 4 * 4;
  char *s = malloc(padded + 1);
  unsigned char *out = calloc(padded + 1, 1);
  if (!s || !out) {
    free(s);
    free(out);
    return NULL;
  }
  for (size_t i = 0; i < n; i++) {
    unsigned char b = (unsigned char)text[i];
    if (!(isalnum(b) || b == '_' || b == '-')) {
      free(s);
      free(out);
      return NULL;
    }
    s[i] = b == '-' ? '+' : b == '_' ? '/' : (char)b;
  }
  for (size_t i = n; i < padded; i++)
    s[i] = '=';
  s[padded] = 0;
  int size = EVP_DecodeBlock(out, (unsigned char *)s, (int)padded);
  free(s);
  if (size < 0 || (size_t)size < padded - n) {
    free(out);
    return NULL;
  }
  *length = (size_t)size - (padded - n);
  char *canonical = enc(out, *length);
  int valid = canonical && !strcmp(canonical, text);
  free(canonical);
  if (!valid) {
    free(out);
    return NULL;
  }
  return out;
}
static int source_valid(const char *source) {
  const char *names[] = {"linux-dmi", "linux-device-tree", "linux-machine-id",
                         "windows-smbios", "macos-platform"};
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
    if (!strcmp(source, names[i]))
      return 1;
  return 0;
}
static int binding_valid(const char *s) {
  if (!s || strncmp(s, "m1:", 3))
    return 0;
  const char *p = strchr(s + 3, ':');
  if (!p || strlen(p + 1) != 64 || (size_t)(p - s) > 40)
    return 0;
  char source[40];
  memcpy(source, s + 3, (size_t)(p - s - 3));
  source[p - s - 3] = 0;
  if (!source_valid(source))
    return 0;
  for (p++; *p; p++)
    if (!isdigit((unsigned char)*p) && !(*p >= 'a' && *p <= 'f'))
      return 0;
  return 1;
}
static int digest(const unsigned char *data, size_t n,
                  unsigned char output[32]) {
  unsigned int size = 0;
  return EVP_Digest(data, n, output, &size, EVP_sha256(), NULL) == 1 &&
         size == 32;
}
static void hex(const unsigned char *bytes, size_t n, char *out) {
  static const char h[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) {
    out[2 * i] = h[bytes[i] >> 4];
    out[2 * i + 1] = h[bytes[i] & 15];
  }
  out[n * 2] = 0;
}
lb_result lb_derive_binding(const char *product, const char *source,
                            const char *raw, char *out, size_t cap) {
  if (!product || !*product || strpbrk(product, "\r\n") || !source ||
      !source_valid(source) || !raw || !out)
    return LB_IDENTITY_UNAVAILABLE;
  size_t n = strlen(raw);
  while (n && isspace((unsigned char)raw[n - 1]))
    n--;
  size_t start = 0;
  while (start < n && isspace((unsigned char)raw[start]))
    start++;
  char id[65];
  size_t count = 0;
  int zero = 1, ones = 1;
  for (size_t i = start; i < n; i++) {
    if (raw[i] == '-')
      continue;
    char b = (char)tolower((unsigned char)raw[i]);
    if (!isxdigit((unsigned char)b) || count >= 64)
      return LB_IDENTITY_UNAVAILABLE;
    id[count++] = b;
    zero = zero && b == '0';
    ones = ones && b == 'f';
  }
  id[count] = 0;
  if (count < 16 || count > 64 || count % 2 ||
      (strcmp(source, "linux-device-tree") && count != 32) || zero || ones)
    return LB_IDENTITY_UNAVAILABLE;
  char *namespace = format("licensebox machine binding v1\n%s", product),
       *message = format("%s\n%s", source, id);
  unsigned char key[32], sum[32];
  unsigned int size = 0;
  if (!namespace || !message) {
    free(namespace);
    free(message);
    return LB_IO_ERROR;
  }
  int ok = digest((unsigned char *)namespace, strlen(namespace), key) &&
           HMAC(EVP_sha256(), key, 32, (unsigned char *)message,
                strlen(message), sum, &size) &&
           size == 32;
  free(namespace);
  free(message);
  OPENSSL_cleanse(key, sizeof(key));
  if (!ok)
    return LB_PROTOCOL_ERROR;
  char h[65];
  hex(sum, 32, h);
  int needed = snprintf(out, cap, "m1:%s:%s", source, h);
  return needed >= 0 && (size_t)needed < cap ? LB_OK : LB_INVALID_ARGUMENT;
}
static char *read_path(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return NULL;
  char *s = calloc(LIMIT + 1, 1);
  if (!s) {
    fclose(f);
    return NULL;
  }
  size_t n = fread(s, 1, LIMIT, f);
  int bad = ferror(f) || !feof(f);
  fclose(f);
  if (bad) {
    free(s);
    return NULL;
  }
  while (n && (s[n - 1] == 0 || isspace((unsigned char)s[n - 1])))
    s[--n] = 0;
  return s;
}
lb_result lb_native_binding(const char *product, char *out, size_t cap) {
  const char *paths[] = {"/sys/class/dmi/id/product_uuid",
                         "/sys/firmware/devicetree/base/serial-number",
                         "/etc/machine-id", "/var/lib/dbus/machine-id"};
  const char *sources[] = {"linux-dmi", "linux-device-tree", "linux-machine-id",
                           "linux-machine-id"};
  for (size_t i = 0; i < 4; i++) {
    char *id = read_path(paths[i]);
    if (!id)
      continue;
    lb_result r = lb_derive_binding(product, sources[i], id, out, cap);
    OPENSSL_cleanse(id, strlen(id));
    free(id);
    if (r == LB_OK)
      return r;
  }
  return LB_IDENTITY_UNAVAILABLE;
}
static int timestamp(const char *s, double *result) {
  int y, m, d, h, minute, second, n = 0;
  if (!s || sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d%n", &y, &m, &d, &h, &minute,
                   &second, &n) != 6)
    return 0;
  if (m < 1 || m > 12 || d < 1 || d > 31 || h > 23 || minute > 59 ||
      second > 59 || h < 0 || minute < 0 || second < 0)
    return 0;
  struct tm value = {.tm_year = y - 1900,
                     .tm_mon = m - 1,
                     .tm_mday = d,
                     .tm_hour = h,
                     .tm_min = minute,
                     .tm_sec = second},
            check;
  time_t seconds = timegm(&value);
  gmtime_r(&seconds, &check);
  if (check.tm_year != y - 1900 || check.tm_mon != m - 1 || check.tm_mday != d)
    return 0;
  const char *p = s + n;
  double fraction = 0, scale = 0.1;
  if (*p == '.') {
    p++;
    if (!isdigit((unsigned char)*p))
      return 0;
    while (isdigit((unsigned char)*p)) {
      fraction += (*p++ - '0') * scale;
      scale *= 0.1;
    }
  }
  int offset = 0;
  if (*p == 'Z' && !p[1])
    p++;
  else if (*p == '+' || *p == '-') {
    int sign = *p++ == '+' ? 1 : -1, oh, om, end = 0;
    if (sscanf(p, "%2d:%2d%n", &oh, &om, &end) != 2 || oh < 0 || oh > 23 ||
        om < 0 || om > 59 || p[end])
      return 0;
    offset = sign * (oh * 3600 + om * 60);
    p += end;
  } else
    return 0;
  if (*p)
    return 0;
  *result = (double)seconds + fraction - offset;
  return 1;
}
static void stamp(double seconds, char output[40]) {
  time_t t = (time_t)floor(seconds);
  struct tm value;
  gmtime_r(&t, &value);
  strftime(output, 40, "%Y-%m-%dT%H:%M:%SZ", &value);
}
static lb_result verify_internal(const char *token, const char *product,
                                 const lb_public_key *keys, size_t key_count,
                                 double now, int expired, J **output) {
  *output = NULL;
  if (!token || !product || !keys || !key_count || strlen(token) > LIMIT)
    return LB_MALFORMED;
  char *copy = strdup(token);
  if (!copy)
    return LB_IO_ERROR;
  char *dot = strchr(copy, '.');
  if (!dot || strchr(dot + 1, '.')) {
    free(copy);
    return LB_MALFORMED;
  }
  *dot++ = 0;
  size_t pn = 0, sn = 0;
  unsigned char *payload = dec(copy, &pn), *signature = dec(dot, &sn);
  free(copy);
  if (!payload || !signature || sn != 64 || memchr(payload, 0, pn)) {
    free(payload);
    free(signature);
    return LB_MALFORMED;
  }
  J *o = parse((char *)payload);
  lb_result r = LB_OK;
  if (!o || !json_object_is_type(o, json_type_object)) {
    r = LB_MALFORMED;
    goto done;
  }
  if (json_object_get_int(get(o, "v")) != 2) {
    r = LB_VERSION;
    goto done;
  }
  const char *public = NULL;
  for (size_t i = 0; i < key_count; i++)
    if (keys[i].id && !strcmp(keys[i].id, field(o, "kid"))) {
      public = keys[i].public_key;
      break;
    }
  if (!public) {
    r = LB_UNKNOWN_KEY;
    goto done;
  }
  size_t kn = 0;
  unsigned char *kb = dec(public, &kn);
  if (!kb || kn != 32) {
    free(kb);
    r = LB_MALFORMED;
    goto done;
  }
  EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, kb, kn);
  free(kb);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  size_t prefix = strlen("licensebox lease v2\n");
  unsigned char *message = malloc(prefix + pn);
  if (!key || !ctx || !message) {
    EVP_PKEY_free(key);
    EVP_MD_CTX_free(ctx);
    free(message);
    r = LB_IO_ERROR;
    goto done;
  }
  memcpy(message, "licensebox lease v2\n", prefix);
  memcpy(message + prefix, payload, pn);
  int valid = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
              EVP_DigestVerify(ctx, signature, sn, message, prefix + pn) == 1;
  EVP_PKEY_free(key);
  EVP_MD_CTX_free(ctx);
  free(message);
  if (!valid) {
    r = LB_BAD_SIGNATURE;
    goto done;
  }
  if (strcmp(field(o, "product"), product) ||
      !binding_valid(field(o, "binding"))) {
    r = LB_MALFORMED;
    goto done;
  }
  size_t mn = 0;
  unsigned char *machine = dec(field(o, "machine"), &mn);
  free(machine);
  if (mn != 32) {
    r = LB_MALFORMED;
    goto done;
  }
  J *modules = get(o, "modules");
  if (!modules || !json_object_is_type(modules, json_type_array)) {
    r = LB_MALFORMED;
    goto done;
  }
  for (size_t i = 0; i < json_object_array_length(modules); i++)
    if (!json_object_is_type(json_object_array_get_idx(modules, i),
                             json_type_string)) {
      r = LB_MALFORMED;
      goto done;
    }
  double until = 0;
  if (!timestamp(field(o, "expires"), &until)) {
    r = LB_MALFORMED;
    goto done;
  }
  if (!expired && now >= until) {
    r = LB_EXPIRED;
    goto done;
  }
  *output = o;
  o = NULL;
done:
  free(payload);
  free(signature);
  json_object_put(o);
  return r;
}
lb_result lb_verify_lease(const char *token, const char *product,
                          const lb_public_key *keys, size_t n, double now,
                          char **output) {
  if (!output)
    return LB_INVALID_ARGUMENT;
  *output = NULL;
  J *o = NULL;
  lb_result r = verify_internal(token, product, keys, n, now, 0, &o);
  if (r == LB_OK) {
    *output = strdup(json(o));
    if (!*output)
      r = LB_IO_ERROR;
  }
  json_object_put(o);
  return r;
}
static lb_result mkdirs(lb_client *c) {
  char *path = strdup(c->directory);
  if (!path)
    return fail(c, LB_IO_ERROR, NULL, NULL);
  for (char *p = path + 1;; p++) {
    if (*p != '/' && *p)
      continue;
    char saved = *p;
    *p = 0;
    if (mkdir(path, 0700) && errno != EEXIST) {
      free(path);
      return fail(c, LB_IO_ERROR, NULL, "cannot create licence directory");
    }
    *p = saved;
    if (!saved)
      break;
  }
  free(path);
  return LB_OK;
}
static char *read_state(lb_client *c, const char *name) {
  char *path = format("%s/%s", c->directory, name);
  if (!path)
    return NULL;
  char *s = read_path(path);
  free(path);
  return s;
}
static lb_result write_state(lb_client *c, const char *name, const char *text) {
  if (!text || mkdirs(c) != LB_OK)
    return fail(c, LB_IO_ERROR, NULL, "cannot write licence state");
  char *path = format("%s/%s", c->directory, name),
       *temporary = format("%s/.tmp-XXXXXX", c->directory);
  int fd = -1;
  lb_result result = LB_OK;
  if (!path || !temporary || (fd = mkstemp(temporary)) < 0) {
    result = LB_IO_ERROR;
    goto done;
  }
  if (fchmod(fd, 0600)) {
    result = LB_IO_ERROR;
    goto done;
  }
  size_t n = strlen(text), written = 0;
  while (written < n) {
    ssize_t amount = write(fd, text + written, n - written);
    if (amount < 0 && errno == EINTR)
      continue;
    if (amount <= 0) {
      result = LB_IO_ERROR;
      goto done;
    }
    written += (size_t)amount;
  }
  if (write(fd, "\n", 1) != 1) {
    result = LB_IO_ERROR;
    goto done;
  }
  if (close(fd)) {
    fd = -1;
    result = LB_IO_ERROR;
    goto done;
  }
  fd = -1;
  if (rename(temporary, path))
    result = LB_IO_ERROR;
done:
  if (fd >= 0)
    close(fd);
  if (temporary)
    unlink(temporary);
  free(path);
  free(temporary);
  return result == LB_OK ? LB_OK
                         : fail(c, result, NULL, "cannot write licence state");
}
static void remove_state(lb_client *c, const char *name) {
  char *path = format("%s/%s", c->directory, name);
  if (path) {
    unlink(path);
    free(path);
  }
}
static void forget(lb_client *c) {
  json_object_put(c->checked);
  c->checked = NULL;
  const char *names[] = {"lease", "usage.json", "usage-on", "policy-denial"};
  for (size_t i = 0; i < 4; i++)
    remove_state(c, names[i]);
}
static double raw_now(lb_client *c) {
  if (c->callbacks.clock)
    return c->callbacks.clock(c->callbacks.context);
  struct timespec t;
  clock_gettime(CLOCK_REALTIME, &t);
  return (double)t.tv_sec + t.tv_nsec / 1e9;
}
static lb_result now_seen(lb_client *c, double *out) {
  *out = raw_now(c);
  char *seen = read_state(c, "seen");
  double old = 0;
  if (seen) {
    if (!timestamp(seen, &old)) {
      free(seen);
      return fail(c, LB_IO_ERROR, NULL, "saved clock is damaged");
    }
    if (old > *out)
      *out = old;
    free(seen);
  }
  char at[40];
  stamp(*out, at);
  return write_state(c, "seen", at);
}
static lb_result binding(lb_client *c) {
  if (c->binding[0])
    return LB_OK;
  lb_result r = LB_OK;
  if (c->callbacks.machine_binding) {
    if (c->callbacks.machine_binding(c->callbacks.context, c->binding,
                                     sizeof(c->binding)))
      r = LB_IDENTITY_UNAVAILABLE;
    c->binding[sizeof(c->binding) - 1] = 0;
  } else
    r = lb_native_binding(c->product, c->binding, sizeof(c->binding));
  if (r != LB_OK || !binding_valid(c->binding)) {
    c->binding[0] = 0;
    return fail(c, LB_IDENTITY_UNAVAILABLE, NULL,
                "a stable native machine identity is unavailable");
  }
  return LB_OK;
}
static lb_result install_key(lb_client *c, EVP_PKEY **output) {
  *output = NULL;
  if (mkdirs(c) != LB_OK)
    return c->result;
  char *path = format("%s/install.key", c->directory);
  if (!path)
    return fail(c, LB_IO_ERROR, NULL, NULL);
  for (int i = 0; i < 40; i++) {
    char *saved = read_state(c, "install.key");
    size_t n = 0;
    unsigned char *seed = saved ? dec(saved, &n) : NULL;
    free(saved);
    if (seed && n == 32) {
      *output = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, n);
      OPENSSL_cleanse(seed, n);
      free(seed);
      free(path);
      return *output ? LB_OK : fail(c, LB_PROTOCOL_ERROR, NULL, NULL);
    }
    free(seed);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
      if (errno == EEXIST) {
        usleep(25000);
        continue;
      }
      break;
    }
    unsigned char raw[32];
    int ok = RAND_priv_bytes(raw, 32) == 1;
    char *text = ok ? enc(raw, 32) : NULL;
    if (text) {
      char *line = format("%s\n", text);
      if (!line)
        ok = 0;
      else {
        ok = write(fd, line, strlen(line)) == (ssize_t)strlen(line);
        OPENSSL_cleanse(line, strlen(line));
        free(line);
      }
    } else
      ok = 0;
    if (close(fd))
      ok = 0;
    if (ok)
      *output = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, raw, 32);
    OPENSSL_cleanse(raw, sizeof(raw));
    if (text) {
      OPENSSL_cleanse(text, strlen(text));
      free(text);
    }
    if (!ok || !*output)
      unlink(path);
    free(path);
    return ok && *output
               ? LB_OK
               : fail(c, LB_IO_ERROR, NULL, "cannot create installation key");
  }
  free(path);
  return fail(c, LB_IO_ERROR, NULL,
              "installation key is damaged or another process is writing it");
}
static char *public_key(EVP_PKEY *key) {
  unsigned char b[32];
  size_t n = sizeof(b);
  return EVP_PKEY_get_raw_public_key(key, b, &n) == 1 && n == 32 ? enc(b, n)
                                                                 : NULL;
}
static char *signature(EVP_PKEY *key, const char *message) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  unsigned char sig[64];
  size_t n = sizeof(sig);
  char *text = NULL;
  if (ctx && message && EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1 &&
      EVP_DigestSign(ctx, sig, &n, (const unsigned char *)message,
                     strlen(message)) == 1 &&
      n == 64)
    text = enc(sig, n);
  EVP_MD_CTX_free(ctx);
  return text;
}
static lb_result own(lb_client *c, J *lease) {
  if (binding(c) != LB_OK)
    return c->result;
  if (strcmp(field(lease, "binding"), c->binding))
    return fail(
        c, LB_MACHINE_CHANGED, NULL,
        "these credentials belong to another machine; explicitly sign in here");
  EVP_PKEY *key = NULL;
  if (install_key(c, &key) != LB_OK)
    return c->result;
  char *public = public_key(key);
  EVP_PKEY_free(key);
  int valid = public && !strcmp(public, field(lease, "machine"));
  free(public);
  return valid ? LB_OK
               : fail(c, LB_MACHINE_CHANGED, NULL,
                      "these credentials belong to another installation; "
                      "explicitly sign in here");
}
static lb_result policy_code(const char *code) {
  for (int r = LB_MACHINE_CHANGED; r <= LB_LOCATION_UNKNOWN; r++)
    if (!strcmp(code, codes[r]))
      return (lb_result)r;
  return LB_OK;
}
static lb_result denial(lb_client *c) {
  errno = 0;
  char *saved = read_state(c, "policy-denial");
  if (!saved)
    return errno == ENOENT
               ? LB_OK
               : fail(c, LB_IO_ERROR, NULL,
                      "cannot read saved policy refusal; connect to renew");
  J *o = parse(saved);
  free(saved);
  lb_result r = policy_code(field(o, "code"));
  if (r == LB_OK)
    r = fail(c, LB_IO_ERROR, NULL,
             "saved policy refusal is damaged; connect to renew");
  else
    fail(c, r, field(o, "code"), field(o, "detail"));
  json_object_put(o);
  return r;
}
static pthread_once_t curl_once = PTHREAD_ONCE_INIT;
static CURLcode curl_init_result;
static void curl_init(void) {
  curl_init_result = curl_global_init(CURL_GLOBAL_DEFAULT);
}
typedef struct {
  char *data;
  size_t size;
  int overflow;
} response_buffer;
static size_t receive(char *data, size_t size, size_t n, void *context) {
  response_buffer *b = context;
  if (size && n > SIZE_MAX / size) {
    b->overflow = 1;
    return 0;
  }
  size_t amount = size * n;
  if (amount > LIMIT - b->size) {
    b->overflow = 1;
    return 0;
  }
  char *p = realloc(b->data, b->size + amount + 1);
  if (!p)
    return 0;
  b->data = p;
  memcpy(p + b->size, data, amount);
  b->size += amount;
  p[b->size] = 0;
  return amount;
}
static int cancelled(lb_client *c) {
  return c->callbacks.cancelled && c->callbacks.cancelled(c->callbacks.context);
}
static int progress(void *context, curl_off_t a, curl_off_t b, curl_off_t d,
                    curl_off_t e) {
  (void)a;
  (void)b;
  (void)d;
  (void)e;
  return cancelled(context);
}
static lb_result post(lb_client *c, const char *path, J *request, long timeout,
                      J **output) {
  *output = NULL;
  c->status = 0;
  if (cancelled(c))
    return fail(c, LB_CANCELLED, NULL, NULL);
  CURL *curl = curl_easy_init();
  char *url = format("%s%s", c->server, path);
  response_buffer b = {0};
  struct curl_slist *headers = NULL;
  lb_result r = LB_OK;
  if (!curl || !url) {
    r = fail(c, LB_IO_ERROR, NULL, NULL);
    goto done;
  }
  headers = curl_slist_append(NULL, "Content-Type: application/json");
  if (!headers) {
    r = fail(c, LB_IO_ERROR, NULL, NULL);
    goto done;
  }
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json(request));
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &b);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout > 0 ? timeout : 1L);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
  curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
  if (c->ca_bundle)
    curl_easy_setopt(curl, CURLOPT_CAINFO, c->ca_bundle);
  curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
  curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, progress);
  curl_easy_setopt(curl, CURLOPT_XFERINFODATA, c);
  CURLcode result = curl_easy_perform(curl);
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &c->status);
  if (result != CURLE_OK) {
    r = fail(c,
             cancelled(c) ? LB_CANCELLED
             : b.overflow ? LB_PROTOCOL_ERROR
                          : LB_NETWORK_ERROR,
             NULL,
             b.overflow ? "server response exceeded size limit"
                        : "cannot reach the licensing server");
    goto done;
  }
  J *answer = parse(b.data ? b.data : "");
  if (c->status != 200) {
    const char *code = field(answer, "error"),
               *detail = field(answer, "error_description");
    if (!*code)
      code = "http_error";
    lb_result p = policy_code(code);
    if (p != LB_OK) {
      J *saved = json_object_new_object();
      add(saved, "code", code);
      add(saved, "detail", *detail ? detail : code);
      lb_result wrote = write_state(c, "policy-denial", json(saved));
      json_object_put(saved);
      if (wrote != LB_OK) {
        json_object_put(answer);
        r = wrote;
        goto done;
      }
      r = fail(c, p, code, *detail ? detail : code);
    } else if (!strcmp(code, "revoked")) {
      forget(c);
      r = fail(c, LB_REVOKED, code, *detail ? detail : code);
    } else
      r = fail(c, LB_HTTP_ERROR, code, *detail ? detail : code);
    json_object_put(answer);
    goto done;
  }
  if (!answer) {
    r = fail(c, LB_PROTOCOL_ERROR, NULL, "invalid server JSON");
    goto done;
  }
  *output = answer;
done:
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  free(url);
  free(b.data);
  return r;
}
static lb_result save(lb_client *c, const char *token, J **out) {
  double now;
  if (now_seen(c, &now) != LB_OK)
    return c->result;
  lb_result r =
      verify_internal(token, c->product, c->keys, c->key_count, now, 0, out);
  if (r != LB_OK)
    return fail(c, r, NULL, "the server sent an invalid lease");
  if (own(c, *out) != LB_OK) {
    json_object_put(*out);
    *out = NULL;
    return c->result;
  }
  r = write_state(c, "lease", token);
  if (r != LB_OK) {
    json_object_put(*out);
    *out = NULL;
    return r;
  }
  remove_state(c, "policy-denial");
  return LB_OK;
}
static lb_result call(lb_client *c, const char *kind, J *payload, long timeout,
                      J **out) {
  char *token = read_state(c, "lease");
  J *kept = NULL;
  lb_result r = verify_internal(token, c->product, c->keys, c->key_count,
                                raw_now(c), 1, &kept);
  if (r != LB_OK) {
    free(token);
    return fail(c, r, NULL, NULL);
  }
  r = own(c, kept);
  json_object_put(kept);
  if (r != LB_OK) {
    free(token);
    return r;
  }
  EVP_PKEY *key = NULL;
  if (install_key(c, &key) != LB_OK) {
    free(token);
    return c->result;
  }
  char at[40], h[65];
  stamp(raw_now(c), at);
  unsigned char sum[32];
  const char *body = json(payload);
  if (!digest((const unsigned char *)body, strlen(body), sum)) {
    free(token);
    EVP_PKEY_free(key);
    return fail(c, LB_PROTOCOL_ERROR, NULL, NULL);
  }
  hex(sum, 32, h);
  char *message = format("licensebox %s v2\n%s\n%s\n%s\n%s", kind, token,
                         c->binding, at, h),
       *sig = signature(key, message), *path = format("/v1/%s", kind);
  EVP_PKEY_free(key);
  free(message);
  if (!sig || !path) {
    free(token);
    free(sig);
    free(path);
    return fail(c, LB_IO_ERROR, NULL, NULL);
  }
  J *request = json_object_new_object();
  add(request, "lease", token);
  add(request, "binding", c->binding);
  add(request, "time", at);
  add(request, "payload", body);
  add(request, "version", c->version);
  add(request, "signature", sig);
  r = post(c, path, request, timeout, out);
  json_object_put(request);
  free(token);
  free(sig);
  free(path);
  return r;
}
static J *usage(lb_client *c) {
  char *saved = read_state(c, "usage.json");
  J *o = saved ? parse(saved) : NULL;
  free(saved);
  if (!json_object_is_type(o, json_type_array)) {
    json_object_put(o);
    o = json_object_new_array();
  }
  return o;
}
static lb_result usage_sent(lb_client *c, J *sent, int enabled) {
  if (write_state(c, "usage-on", enabled ? "on" : "off") != LB_OK)
    return c->result;
  if (!sent || !json_object_array_length(sent))
    return LB_OK;
  J *queued = usage(c), *remaining = json_object_new_array();
  for (size_t i = 0; i < json_object_array_length(queued); i++) {
    J *item = json_object_array_get_idx(queued, i);
    int found = 0;
    for (size_t j = 0; j < json_object_array_length(sent); j++)
      if (json_object_equal(item, json_object_array_get_idx(sent, j))) {
        found = 1;
        break;
      }
    if (!found)
      json_object_array_add(remaining, json_object_get(item));
  }
  lb_result r = write_state(c, "usage.json", json(remaining));
  json_object_put(queued);
  json_object_put(remaining);
  return r;
}
static lb_result renew(lb_client *c, J **out) {
  *out = NULL;
  J *queued = usage(c), *sent = json_object_new_array();
  for (size_t i = 0; i < json_object_array_length(queued) && i < 100; i++)
    json_object_array_add(
        sent, json_object_get(json_object_array_get_idx(queued, i)));
  json_object_put(queued);
  J *payload = json_object_new_object(), *response = NULL;
  json_object_object_add(payload, "usage", json_object_get(sent));
  lb_result r = call(c, "renew", payload, 3000, &response);
  json_object_put(payload);
  if (r == LB_OK)
    r = save(c, field(response, "lease"), out);
  if (r == LB_OK)
    r = usage_sent(c, sent, json_object_get_boolean(get(response, "usage")));
  if (r != LB_OK) {
    json_object_put(*out);
    *out = NULL;
  }
  json_object_put(sent);
  json_object_put(response);
  return r;
}
static lb_result rotate(lb_client *c) {
  unsigned char raw[32];
  if (RAND_priv_bytes(raw, 32) != 1)
    return fail(c, LB_PROTOCOL_ERROR, NULL, NULL);
  char *seed = enc(raw, 32);
  OPENSSL_cleanse(raw, 32);
  if (!seed)
    return fail(c, LB_IO_ERROR, NULL, NULL);
  lb_result r = write_state(c, "install.key", seed);
  OPENSSL_cleanse(seed, strlen(seed));
  free(seed);
  if (r == LB_OK)
    forget(c);
  return r;
}
static double monotonic(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec + t.tv_nsec / 1e9;
}
static lb_result activate(lb_client *c, int explicit, double timeout,
                          int rotated, J **out) {
  *out = NULL;
  if (binding(c) != LB_OK)
    return c->result;
  char *old_token = read_state(c, "lease");
  J *old = NULL;
  verify_internal(old_token, c->product, c->keys, c->key_count, raw_now(c), 1,
                  &old);
  free(old_token);
  if (old && strcmp(field(old, "binding"), c->binding)) {
    if (!explicit) {
      json_object_put(old);
      return fail(c, LB_MACHINE_CHANGED, NULL,
                  "explicitly sign in to activate here");
    }
    if (rotate(c) != LB_OK) {
      json_object_put(old);
      return c->result;
    }
    rotated = 1;
  }
  EVP_PKEY *key = NULL;
  lb_result r = install_key(c, &key);
  if (r != LB_OK) {
    json_object_put(old);
    return r;
  }
  char at[40];
  stamp(raw_now(c), at);
  char *message = format("licensebox device v2\n%s\n%s\n%s", c->product,
                         c->binding, at),
       *sig = signature(key, message), *public = public_key(key);
  free(message);
  if (!sig || !public) {
    free(sig);
    free(public);
    json_object_put(old);
    EVP_PKEY_free(key);
    return fail(c, LB_IO_ERROR, NULL, NULL);
  }
  struct utsname host;
  uname(&host);
  const char *architecture = !strcmp(host.machine, "x86_64")    ? "amd64"
                             : !strcmp(host.machine, "aarch64") ? "arm64"
                                                                : host.machine;
  J *request = json_object_new_object(), *device = NULL;
  add(request, "product", c->product);
  add(request, "binding", c->binding);
  add(request, "machine", public);
  add(request, "os", "linux");
  add(request, "arch", architecture);
  add(request, "version", c->version);
  add(request, "time", at);
  add(request, "signature", sig);
  free(sig);
  free(public);
  r = post(c, "/v1/device", request, 20000, &device);
  json_object_put(request);
  if (r != LB_OK) {
    json_object_put(old);
    EVP_PKEY_free(key);
    if (explicit && !rotated && r == LB_MACHINE_CHANGED) {
      if (rotate(c) != LB_OK)
        return c->result;
      return activate(c, 0, timeout, 1, out);
    }
    return r;
  }
  const char *link = field(device, "verification_uri_complete");
  if (!*link)
    link = field(device, "verification_uri");
  if (c->callbacks.on_sign_in)
    c->callbacks.on_sign_in(c->callbacks.context, link,
                            field(device, "user_code"));
  else
    fprintf(stderr, "%s needs a one-time sign-in.\nOpen %s and enter %s\n",
            c->product, link, field(device, "user_code"));
  double interval = json_object_get_double(get(device, "interval_ms")) / 1000.;
  if (interval <= 0)
    interval = fmax(1, json_object_get_double(get(device, "interval")));
  double life = json_object_get_double(get(device, "expires_in"));
  if (timeout > 0 && timeout < life)
    life = timeout;
  double deadline = monotonic() + life;
  r = LB_SIGN_IN_EXPIRED;
  while (monotonic() < deadline) {
    double wait_until = fmin(deadline, monotonic() + interval);
    while (monotonic() < wait_until) {
      if (cancelled(c)) {
        r = fail(c, LB_CANCELLED, NULL, NULL);
        goto done;
      }
      double sleep = fmin(.05, wait_until - monotonic());
      if (sleep > 0)
        usleep((useconds_t)(sleep * 1e6));
    }
    if (monotonic() >= deadline)
      break;
    stamp(raw_now(c), at);
    message = format("licensebox token v2\n%s\n%s\n%s",
                     field(device, "device_code"), c->binding, at);
    sig = signature(key, message);
    free(message);
    if (!sig) {
      r = fail(c, LB_IO_ERROR, NULL, NULL);
      goto done;
    }
    request = json_object_new_object();
    add(request, "device_code", field(device, "device_code"));
    add(request, "binding", c->binding);
    add(request, "time", at);
    add(request, "signature", sig);
    free(sig);
    J *response = NULL;
    long remaining = (long)((deadline - monotonic()) * 1000);
    r = post(c, "/v1/token", request, remaining < 20000 ? remaining : 20000,
             &response);
    json_object_put(request);
    if (r == LB_OK) {
      r = save(c, field(response, "lease"), out);
      if (r == LB_OK && old && strcmp(field(old, "user"), field(*out, "user")))
        remove_state(c, "usage.json");
      if (r == LB_OK)
        r = usage_sent(c, NULL,
                       json_object_get_boolean(get(response, "usage")));
      json_object_put(response);
      if (r == LB_OK) {
        json_object_put(c->checked);
        c->checked = json_object_get(*out);
      } else {
        json_object_put(*out);
        *out = NULL;
      }
      goto done;
    }
    if (!strcmp(c->code, "authorization_pending"))
      continue;
    if (!strcmp(c->code, "slow_down")) {
      interval += 5;
      continue;
    }
    if (r == LB_NETWORK_ERROR || c->status >= 500)
      continue;
    if (!strcmp(c->code, "access_denied"))
      r = fail(c, LB_DENIED, NULL, NULL);
    else if (!strcmp(c->code, "expired_token"))
      r = fail(c, LB_SIGN_IN_EXPIRED, NULL, NULL);
    goto done;
  }
  r = fail(c, LB_SIGN_IN_EXPIRED, NULL, NULL);
done:
  json_object_put(device);
  json_object_put(old);
  EVP_PKEY_free(key);
  return r;
}
static lb_result get_lease(lb_client *c, J **out) {
  *out = NULL;
  if (binding(c) != LB_OK)
    return c->result;
  double now;
  if (now_seen(c, &now) != LB_OK)
    return c->result;
  double expires = 0;
  int blocked = denial(c) != LB_OK;
  if (c->checked && !blocked &&
      timestamp(field(c->checked, "expires"), &expires) && now < expires) {
    *out = json_object_get(c->checked);
    return LB_OK;
  }
  char *token = read_state(c, "lease");
  if (!token || !*token) {
    free(token);
    return activate(c, 0, 0, 0, out);
  }
  J *kept = NULL;
  lb_result r =
      verify_internal(token, c->product, c->keys, c->key_count, now, 1, &kept);
  free(token);
  if (r != LB_OK)
    return activate(c, 0, 0, 0, out);
  r = own(c, kept);
  if (r != LB_OK) {
    json_object_put(kept);
    return r;
  }
  r = renew(c, out);
  if (r == LB_OK) {
    json_object_put(c->checked);
    c->checked = json_object_get(*out);
    json_object_put(kept);
    return LB_OK;
  }
  if (!strcmp(c->code, "invalid_lease") || !strcmp(c->code, "terms_changed")) {
    json_object_put(kept);
    return activate(c, 0, 0, 0, out);
  }
  if (policy_code(c->code) != LB_OK || r == LB_REVOKED ||
      (c->status >= 300 && c->status < 500)) {
    json_object_put(kept);
    return r;
  }
  lb_result saved = denial(c);
  if (saved != LB_OK) {
    json_object_put(kept);
    return saved;
  }
  if (r == LB_NETWORK_ERROR || c->status >= 500) {
    timestamp(field(kept, "expires"), &expires);
    if (now < expires) {
      *out = kept;
      return LB_OK;
    }
    r = fail(c, LB_OFFLINE, NULL,
             "the offline lease expired; connect to the internet");
  }
  json_object_put(kept);
  return r;
}
static lb_result output_json(lb_client *c, J *o, char **out) {
  if (!out)
    return fail(c, LB_INVALID_ARGUMENT, NULL, NULL);
  *out = strdup(json(o));
  return *out ? LB_OK : fail(c, LB_IO_ERROR, NULL, NULL);
}
static void reset(lb_client *c) {
  c->status = 0;
  fail(c, LB_OK, NULL, NULL);
}
static int has_module(J *lease, const char *module) {
  J *a = get(lease, "modules");
  for (size_t i = 0; i < json_object_array_length(a); i++)
    if (!strcmp(str(json_object_array_get_idx(a, i)), module))
      return 1;
  return 0;
}
lb_result lb_client_create(const lb_config *cfg, lb_client **out) {
  if (!out)
    return LB_INVALID_ARGUMENT;
  *out = NULL;
  if (!cfg || !cfg->product || !*cfg->product || !cfg->keys ||
      !cfg->key_count || cfg->key_count > 1024 || strlen(cfg->product) > 80 ||
      !isalnum((unsigned char)cfg->product[0]))
    return LB_INVALID_ARGUMENT;
  for (const char *p = cfg->product; *p; p++)
    if (!isalnum((unsigned char)*p) && *p != '.' && *p != '_' && *p != '-')
      return LB_INVALID_ARGUMENT;
  pthread_once(&curl_once, curl_init);
  if (curl_init_result != CURLE_OK)
    return LB_HTTP_ERROR;
  lb_client *c = calloc(1, sizeof(*c));
  if (!c)
    return LB_IO_ERROR;
  pthread_mutex_init(&c->mutex, NULL);
  c->callbacks = *cfg;
  c->product = strdup(cfg->product);
  c->version = strdup(cfg->version ? cfg->version : "");
  c->server = strdup(cfg->server ? cfg->server : "https://licensebox.dev");
  c->keys = calloc(cfg->key_count, sizeof(*c->keys));
  if (!c->product || !c->version || !c->server || !c->keys) {
    lb_client_destroy(c);
    return LB_IO_ERROR;
  }
  size_t length = strlen(c->server);
  while (length && c->server[length - 1] == '/')
    c->server[--length] = 0;
  CURLU *url = curl_url();
  char *scheme = NULL, *host = NULL, *user = NULL, *query = NULL,
       *fragment = NULL;
  int valid = url &&
              curl_url_set(url, CURLUPART_URL, c->server, 0) == CURLUE_OK &&
              curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) == CURLUE_OK &&
              curl_url_get(url, CURLUPART_HOST, &host, 0) == CURLUE_OK;
  if (valid) {
    valid = !strcmp(scheme, "https") ||
            (!strcmp(scheme, "http") &&
             (!strcmp(host, "localhost") || !strcmp(host, "127.0.0.1") ||
              !strcmp(host, "[::1]")));
    if (curl_url_get(url, CURLUPART_USER, &user, 0) == CURLUE_OK ||
        curl_url_get(url, CURLUPART_QUERY, &query, 0) == CURLUE_OK ||
        curl_url_get(url, CURLUPART_FRAGMENT, &fragment, 0) == CURLUE_OK)
      valid = 0;
  }
  curl_free(scheme);
  curl_free(host);
  curl_free(user);
  curl_free(query);
  curl_free(fragment);
  curl_url_cleanup(url);
  if (!valid) {
    lb_client_destroy(c);
    return LB_INVALID_ARGUMENT;
  }
  for (size_t i = 0; i < cfg->key_count; i++) {
    size_t n = 0;
    unsigned char *raw = dec(cfg->keys[i].public_key, &n);
    int valid_key = raw != NULL && n == 32;
    free(raw);
    if (!cfg->keys[i].id || !valid_key) {
      lb_client_destroy(c);
      return LB_INVALID_ARGUMENT;
    }
    c->keys[i].id = strdup(cfg->keys[i].id);
    c->keys[i].public_key = strdup(cfg->keys[i].public_key);
    c->key_count = i + 1;
    if (!c->keys[i].id || !c->keys[i].public_key) {
      lb_client_destroy(c);
      return LB_IO_ERROR;
    }
  }
  if (cfg->directory)
    c->directory = strdup(cfg->directory);
  else {
    const char *base = getenv("XDG_CONFIG_HOME");
    if (base && *base)
      c->directory = format("%s/licensebox/%s", base, c->product);
    else {
      base = getenv("HOME");
      if (base && *base)
        c->directory = format("%s/.config/licensebox/%s", base, c->product);
    }
  }
  if (!c->directory || !*c->directory) {
    lb_client_destroy(c);
    return LB_IO_ERROR;
  }
  reset(c);
  *out = c;
  return LB_OK;
}
void lb_client_destroy(lb_client *c) {
  if (!c)
    return;
  json_object_put(c->checked);
  for (size_t i = 0; i < c->key_count; i++) {
    free((void *)c->keys[i].id);
    free((void *)c->keys[i].public_key);
  }
  free(c->keys);
  free(c->product);
  free(c->version);
  free(c->server);
  free(c->directory);
  free(c->ca_bundle);
  pthread_mutex_destroy(&c->mutex);
  free(c);
}
lb_result lb_client_set_ca_bundle(lb_client *c, const char *path) {
  if (!c || (path && !*path))
    return LB_INVALID_ARGUMENT;
  pthread_mutex_lock(&c->mutex);
  reset(c);
  char *copy = path ? strdup(path) : NULL;
  lb_result result = LB_OK;
  if (path && !copy)
    result = fail(c, LB_IO_ERROR, NULL, NULL);
  else {
    free(c->ca_bundle);
    c->ca_bundle = copy;
  }
  pthread_mutex_unlock(&c->mutex);
  return result;
}
lb_result lb_lease(lb_client *c, char **out) {
  if (!c || !out)
    return LB_INVALID_ARGUMENT;
  *out = NULL;
  pthread_mutex_lock(&c->mutex);
  reset(c);
  J *o = NULL;
  lb_result r = get_lease(c, &o);
  if (r == LB_OK)
    r = output_json(c, o, out);
  json_object_put(o);
  pthread_mutex_unlock(&c->mutex);
  return r;
}
lb_result lb_require(lb_client *c, const char *module, char **out) {
  if (!c || !out || !module)
    return LB_INVALID_ARGUMENT;
  *out = NULL;
  pthread_mutex_lock(&c->mutex);
  reset(c);
  J *o = NULL;
  lb_result r = get_lease(c, &o);
  if (r == LB_OK && !has_module(o, module) && !c->checked) {
    J *fresh = NULL;
    lb_result checked = renew(c, &fresh);
    if (checked == LB_OK) {
      json_object_put(o);
      o = fresh;
      c->checked = json_object_get(o);
    } else if (policy_code(c->code) != LB_OK ||
               (checked != LB_NETWORK_ERROR && c->status < 500))
      r = checked;
  }
  if (r == LB_OK && !has_module(o, module))
    r = fail(c, LB_MODULE_DENIED, NULL,
             "the requested module is not licensed to this user");
  if (r == LB_OK)
    r = output_json(c, o, out);
  json_object_put(o);
  pthread_mutex_unlock(&c->mutex);
  return r;
}
lb_result lb_status(lb_client *c, char **out) {
  if (!c || !out)
    return LB_INVALID_ARGUMENT;
  *out = NULL;
  pthread_mutex_lock(&c->mutex);
  reset(c);
  lb_result r = denial(c);
  J *o = NULL;
  char *token = NULL;
  double now = 0;
  if (r == LB_OK) {
    token = read_state(c, "lease");
    if (!token || !*token)
      r = fail(c, LB_NOT_SIGNED_IN, NULL, NULL);
  }
  if (r == LB_OK)
    r = now_seen(c, &now);
  if (r == LB_OK) {
    r = verify_internal(token, c->product, c->keys, c->key_count, now, 1, &o);
    if (r != LB_OK)
      fail(c, r, NULL, NULL);
  }
  if (r == LB_OK)
    r = own(c, o);
  if (r == LB_OK) {
    double until;
    timestamp(field(o, "expires"), &until);
    if (now >= until)
      r = fail(c, LB_EXPIRED, NULL, NULL);
  }
  if (r == LB_OK)
    r = output_json(c, o, out);
  free(token);
  json_object_put(o);
  pthread_mutex_unlock(&c->mutex);
  return r;
}
lb_result lb_sign_in(lb_client *c, double timeout, char **out) {
  if (!c || !out)
    return LB_INVALID_ARGUMENT;
  *out = NULL;
  pthread_mutex_lock(&c->mutex);
  reset(c);
  J *o = NULL;
  lb_result r = activate(c, 1, timeout, 0, &o);
  if (r == LB_OK)
    r = output_json(c, o, out);
  json_object_put(o);
  pthread_mutex_unlock(&c->mutex);
  return r;
}
lb_result lb_logout(lb_client *c) {
  if (!c)
    return LB_INVALID_ARGUMENT;
  pthread_mutex_lock(&c->mutex);
  forget(c);
  reset(c);
  pthread_mutex_unlock(&c->mutex);
  return LB_OK;
}
static lb_result signed_operation(lb_client *c, const char *kind, J *payload,
                                  int link, char **out) {
  if (!c || !out)
    return LB_INVALID_ARGUMENT;
  *out = NULL;
  pthread_mutex_lock(&c->mutex);
  reset(c);
  J *o = NULL;
  lb_result r = get_lease(c, &o);
  json_object_put(o);
  o = NULL;
  if (r == LB_OK)
    r = call(c, kind, payload, 20000, &o);
  if (r == LB_OK) {
    *out = strdup(link ? field(o, "url") : json(o));
    if (!*out)
      r = fail(c, LB_IO_ERROR, NULL, NULL);
  }
  json_object_put(o);
  pthread_mutex_unlock(&c->mutex);
  return r;
}
lb_result lb_modules(lb_client *c, char **out) {
  J *p = json_object_new_object();
  lb_result r = signed_operation(c, "modules", p, 0, out);
  json_object_put(p);
  return r;
}
lb_result lb_requests(lb_client *c, char **out) {
  J *p = json_object_new_object();
  lb_result r = signed_operation(c, "requests", p, 0, out);
  json_object_put(p);
  return r;
}
lb_result lb_access_link(lb_client *c, char **out) {
  J *p = json_object_new_object();
  lb_result r = signed_operation(c, "access-link", p, 1, out);
  json_object_put(p);
  return r;
}
lb_result lb_request_access(lb_client *c, const char *const *modules,
                            size_t count, const char *note, char **out) {
  if (!modules || !count || count > 1024 || !note)
    return LB_INVALID_ARGUMENT;
  J *p = json_object_new_object(), *a = json_object_new_array();
  for (size_t i = 0; i < count; i++) {
    if (!modules[i]) {
      json_object_put(p);
      json_object_put(a);
      return LB_INVALID_ARGUMENT;
    }
    json_object_array_add(a, json_object_new_string(modules[i]));
  }
  json_object_object_add(p, "modules", a);
  add(p, "note", note);
  lb_result r = signed_operation(c, "request", p, 0, out);
  json_object_put(p);
  return r;
}
lb_result lb_record(lb_client *c, const char *command, int success,
                    double elapsed) {
  if (!c || !command || !isfinite(elapsed) || elapsed < 0 || elapsed > 9e12)
    return LB_INVALID_ARGUMENT;
  pthread_mutex_lock(&c->mutex);
  reset(c);
  char *enabled = read_state(c, "usage-on");
  if (!enabled || strcmp(enabled, "on") || !*command || strlen(command) > 64) {
    free(enabled);
    pthread_mutex_unlock(&c->mutex);
    return LB_OK;
  }
  free(enabled);
  J *a = usage(c), *item = NULL;
  char at[40], os[128];
  stamp(raw_now(c), at);
  at[10] = 0;
  struct utsname host;
  uname(&host);
  snprintf(os, sizeof(os), "linux/%s",
           !strcmp(host.machine, "x86_64")    ? "amd64"
           : !strcmp(host.machine, "aarch64") ? "arm64"
                                              : host.machine);
  for (size_t i = 0; i < json_object_array_length(a); i++) {
    J *x = json_object_array_get_idx(a, i);
    if (!strcmp(field(x, "day"), at) && !strcmp(field(x, "command"), command) &&
        !strcmp(field(x, "version"), c->version) &&
        !strcmp(field(x, "os"), os)) {
      item = x;
      break;
    }
  }
  lb_result r = LB_OK;
  if (!item) {
    unsigned char random[16];
    char id[33];
    if (RAND_bytes(random, 16) != 1) {
      json_object_put(a);
      r = fail(c, LB_PROTOCOL_ERROR, NULL, NULL);
      goto done;
    }
    hex(random, 16, id);
    item = json_object_new_object();
    add(item, "id", id);
    add(item, "day", at);
    add(item, "command", command);
    add(item, "version", c->version);
    add(item, "os", os);
    json_object_array_add(a, item);
  }
  const char *counter = success ? "ok" : "failed";
  json_object_object_add(
      item, counter,
      json_object_new_int64(json_object_get_int64(get(item, counter)) + 1));
  const char *other = success ? "failed" : "ok";
  if (!get(item, other))
    json_object_object_add(item, other, json_object_new_int64(0));
  json_object_object_add(
      item, "ms",
      json_object_new_int64(json_object_get_int64(get(item, "ms")) +
                            (int64_t)(elapsed * 1000)));
  if (json_object_array_length(a) > 1000)
    json_object_array_del_idx(a, 0, json_object_array_length(a) - 1000);
  r = write_state(c, "usage.json", json(a));
  json_object_put(a);
done:
  pthread_mutex_unlock(&c->mutex);
  return r;
}
