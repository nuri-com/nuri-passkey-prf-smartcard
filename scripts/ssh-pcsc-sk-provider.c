#define _DARWIN_C_SOURCE
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SSH_SK_USER_PRESENCE_REQD 0x01
#define SSH_SK_USER_VERIFICATION_REQD 0x04
#define SSH_SK_RESIDENT_KEY 0x20
#define SSH_SK_ECDSA 0x00
#define SSH_SK_VERSION_MAJOR 0x000a0000
#define SSH_SK_ERR_GENERAL -1
#define SSH_SK_ERR_UNSUPPORTED -2
#define SSH_SK_ERR_PIN_REQUIRED -3
#define SSH_SK_ERR_DEVICE_NOT_FOUND -4

#ifndef NURI_PCSC_SK_HELPER
#define NURI_PCSC_SK_HELPER "scripts/ssh-pcsc-sk-helper.py"
#endif
#ifndef NURI_PCSC_SK_PYTHON
#define NURI_PCSC_SK_PYTHON "python3"
#endif

struct sk_enroll_response {
    uint8_t flags;
    uint8_t *public_key;
    size_t public_key_len;
    uint8_t *key_handle;
    size_t key_handle_len;
    uint8_t *signature;
    size_t signature_len;
    uint8_t *attestation_cert;
    size_t attestation_cert_len;
    uint8_t *authdata;
    size_t authdata_len;
};

struct sk_sign_response {
    uint8_t flags;
    uint32_t counter;
    uint8_t *sig_r;
    size_t sig_r_len;
    uint8_t *sig_s;
    size_t sig_s_len;
};

struct sk_resident_key {
    uint32_t alg;
    size_t slot;
    char *application;
    struct sk_enroll_response key;
    uint8_t flags;
    uint8_t *user_id;
    size_t user_id_len;
};

struct sk_option {
    char *name;
    char *value;
    uint8_t required;
};

static char *dup_range(const char *start, size_t len) {
    char *out = malloc(len + 1);
    if (out == NULL) return NULL;
    memcpy(out, start, len);
    out[len] = '\0';
    return out;
}

static char *shell_quote(const char *s) {
    size_t len = 3;
    for (const char *p = s; *p; p++) len += (*p == '\'') ? 4 : 1;
    char *out = malloc(len);
    if (out == NULL) return NULL;
    char *q = out;
    *q++ = '\'';
    for (const char *p = s; *p; p++) {
        if (*p == '\'') {
            memcpy(q, "'\\''", 4);
            q += 4;
        } else {
            *q++ = *p;
        }
    }
    *q++ = '\'';
    *q = '\0';
    return out;
}

static char *hex_encode(const uint8_t *buf, size_t len) {
    static const char hexdigits[] = "0123456789abcdef";
    char *out = malloc(len * 2 + 1);
    if (out == NULL) return NULL;
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hexdigits[buf[i] >> 4];
        out[i * 2 + 1] = hexdigits[buf[i] & 15];
    }
    out[len * 2] = '\0';
    return out;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *hex, uint8_t **buf, size_t *len) {
    size_t n = strlen(hex);
    if (n % 2 != 0) return -1;
    *len = n / 2;
    *buf = calloc(1, *len ? *len : 1);
    if (*buf == NULL) return -1;
    for (size_t i = 0; i < *len; i++) {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            free(*buf);
            *buf = NULL;
            *len = 0;
            return -1;
        }
        (*buf)[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static char *value_for(const char *output, const char *key) {
    size_t key_len = strlen(key);
    const char *p = output;
    while (*p) {
        const char *line = p;
        const char *end = strchr(line, '\n');
        size_t line_len = end ? (size_t)(end - line) : strlen(line);
        if (line_len > key_len && memcmp(line, key, key_len) == 0 && line[key_len] == '=') {
            const char *value = line + key_len + 1;
            size_t value_len = line + line_len - value;
            while (value_len > 0 && (value[value_len - 1] == '\r' || value[value_len - 1] == '\n')) value_len--;
            return dup_range(value, value_len);
        }
        p = end ? end + 1 : line + line_len;
    }
    return NULL;
}

static int put_hex_field(const char *output, const char *key, uint8_t **buf, size_t *len, int required) {
    char *hex = value_for(output, key);
    if (hex == NULL) return required ? -1 : 0;
    int ret = hex_decode(hex, buf, len);
    free(hex);
    return ret;
}

static char *read_command(const char *cmd) {
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) return NULL;
    size_t cap = 4096, len = 0;
    char *out = malloc(cap);
    if (out == NULL) {
        pclose(fp);
        return NULL;
    }
    out[0] = '\0';
    char chunk[1024];
    while (fgets(chunk, sizeof(chunk), fp) != NULL) {
        size_t n = strlen(chunk);
        if (len + n + 1 > cap) {
            cap = (len + n + 1) * 2;
            char *tmp = realloc(out, cap);
            if (tmp == NULL) {
                free(out);
                pclose(fp);
                return NULL;
            }
            out = tmp;
        }
        memcpy(out + len, chunk, n);
        len += n;
        out[len] = '\0';
    }
    pclose(fp);
    return out;
}

static int output_error(const char *output) {
    char *status = value_for(output, "status");
    if (status != NULL && strcmp(status, "OK") == 0) {
        free(status);
        return 0;
    }
    free(status);
    char *err = value_for(output, "error");
    int ret = SSH_SK_ERR_GENERAL;
    if (err != NULL) {
        if (strcmp(err, "NO_DEVICE") == 0) ret = SSH_SK_ERR_DEVICE_NOT_FOUND;
        else if (strcmp(err, "UNSUPPORTED") == 0) ret = SSH_SK_ERR_UNSUPPORTED;
        else if (strcmp(err, "PIN_REQUIRED") == 0) ret = SSH_SK_ERR_PIN_REQUIRED;
    }
    free(err);
    return ret;
}

static char *helper_path(void) {
    const char *helper = getenv("NURI_PCSC_SK_HELPER");
    return strdup((helper && *helper) ? helper : NURI_PCSC_SK_HELPER);
}

static char *python_path(void) {
    const char *python = getenv("NURI_PCSC_SK_PYTHON");
    return strdup((python && *python) ? python : NURI_PCSC_SK_PYTHON);
}

static char *run_enroll_helper(const char *application, const uint8_t *challenge, size_t challenge_len, uint8_t flags, const uint8_t user_id[32]) {
    char *python = python_path(), *helper = helper_path();
    char *python_q = shell_quote(python), *helper_q = shell_quote(helper), *app_q = shell_quote(application);
    char *challenge_hex = hex_encode(challenge, challenge_len), *user_hex = hex_encode(user_id, 32);
    char *cmd = NULL, *out = NULL;
    if (python_q && helper_q && app_q && challenge_hex && user_hex &&
        asprintf(&cmd, "%s %s enroll --application %s --challenge-hex %s --flags %u --user-hex %s",
                 python_q, helper_q, app_q, challenge_hex, (unsigned)flags, user_hex) != -1) {
        out = read_command(cmd);
    }
    free(cmd); free(user_hex); free(challenge_hex); free(app_q); free(helper_q); free(python_q); free(helper); free(python);
    return out;
}

static char *run_sign_helper(const char *application, const uint8_t *data, size_t data_len, const uint8_t *key_handle, size_t key_handle_len, uint8_t flags) {
    char *python = python_path(), *helper = helper_path();
    char *python_q = shell_quote(python), *helper_q = shell_quote(helper), *app_q = shell_quote(application);
    char *data_hex = hex_encode(data, data_len), *handle_hex = hex_encode(key_handle, key_handle_len);
    char *cmd = NULL, *out = NULL;
    if (python_q && helper_q && app_q && data_hex && handle_hex &&
        asprintf(&cmd, "%s %s sign --application %s --data-hex %s --key-handle-hex %s --flags %u",
                 python_q, helper_q, app_q, data_hex, handle_hex, (unsigned)flags) != -1) {
        out = read_command(cmd);
    }
    free(cmd); free(handle_hex); free(data_hex); free(app_q); free(helper_q); free(python_q); free(helper); free(python);
    return out;
}

__attribute__((visibility("default"))) uint32_t sk_api_version(void) {
    return SSH_SK_VERSION_MAJOR;
}

__attribute__((visibility("default"))) int sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
    const char *application, uint8_t flags, const char *pin,
    struct sk_option **options, struct sk_enroll_response **enroll_response) {
    (void)pin;
    if (alg != SSH_SK_ECDSA || enroll_response == NULL) return SSH_SK_ERR_UNSUPPORTED;
    *enroll_response = NULL;
    uint8_t user_id[32] = {0};
    for (size_t i = 0; options && options[i]; i++) {
        if (strcmp(options[i]->name, "user") == 0) {
            size_t n = strlen(options[i]->value);
            if (n > sizeof(user_id)) return SSH_SK_ERR_GENERAL;
            memcpy(user_id, options[i]->value, n);
        }
    }
    char *out = run_enroll_helper(application, challenge, challenge_len, flags, user_id);
    if (out == NULL) return SSH_SK_ERR_GENERAL;
    int err = output_error(out);
    if (err != 0) {
        free(out);
        return err;
    }
    struct sk_enroll_response *r = calloc(1, sizeof(*r));
    char *flag_hex = value_for(out, "flags");
    if (r == NULL || flag_hex == NULL) err = SSH_SK_ERR_GENERAL;
    else r->flags = (uint8_t)strtoul(flag_hex, NULL, 16);
    free(flag_hex);
    if (err == 0 && put_hex_field(out, "public_key", &r->public_key, &r->public_key_len, 1) != 0) err = SSH_SK_ERR_GENERAL;
    if (err == 0 && put_hex_field(out, "key_handle", &r->key_handle, &r->key_handle_len, 1) != 0) err = SSH_SK_ERR_GENERAL;
    if (err == 0) put_hex_field(out, "signature", &r->signature, &r->signature_len, 0);
    if (err == 0) put_hex_field(out, "authdata", &r->authdata, &r->authdata_len, 0);
    free(out);
    if (err != 0) {
        if (r) {
            free(r->public_key); free(r->key_handle); free(r->signature); free(r->authdata); free(r);
        }
        return err;
    }
    *enroll_response = r;
    return 0;
}

__attribute__((visibility("default"))) int sk_sign(uint32_t alg, const uint8_t *data, size_t data_len,
    const char *application, const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, const char *pin, struct sk_option **options,
    struct sk_sign_response **sign_response) {
    (void)pin; (void)options;
    if (alg != SSH_SK_ECDSA || sign_response == NULL) return SSH_SK_ERR_UNSUPPORTED;
    *sign_response = NULL;
    char *out = run_sign_helper(application, data, data_len, key_handle, key_handle_len, flags);
    if (out == NULL) return SSH_SK_ERR_GENERAL;
    int err = output_error(out);
    if (err != 0) {
        free(out);
        return err;
    }
    struct sk_sign_response *r = calloc(1, sizeof(*r));
    char *flag_hex = value_for(out, "flags");
    char *counter = value_for(out, "counter");
    if (r == NULL || flag_hex == NULL || counter == NULL) err = SSH_SK_ERR_GENERAL;
    else {
        r->flags = (uint8_t)strtoul(flag_hex, NULL, 16);
        r->counter = (uint32_t)strtoul(counter, NULL, 10);
    }
    free(flag_hex); free(counter);
    if (err == 0 && put_hex_field(out, "sig_r", &r->sig_r, &r->sig_r_len, 1) != 0) err = SSH_SK_ERR_GENERAL;
    if (err == 0 && put_hex_field(out, "sig_s", &r->sig_s, &r->sig_s_len, 1) != 0) err = SSH_SK_ERR_GENERAL;
    free(out);
    if (err != 0) {
        if (r) { free(r->sig_r); free(r->sig_s); free(r); }
        return err;
    }
    *sign_response = r;
    return 0;
}

__attribute__((visibility("default"))) int sk_load_resident_keys(const char *pin, struct sk_option **options,
    struct sk_resident_key ***rks, size_t *nrks) {
    (void)pin; (void)options;
    if (rks == NULL || nrks == NULL) return SSH_SK_ERR_GENERAL;
    *rks = NULL;
    *nrks = 0;
    return 0;
}
