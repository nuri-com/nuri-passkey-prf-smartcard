/* pkcs11-nuri.c — Minimal PKCS#11 module for Nuri smartcard.
 * Delegates signing to scripts/pkcs11-helper.py over stdin/stdout.
 * 
 * Build: scripts/build-pkcs11.sh (one clang command, see there).
 *
 * Test (sim, no card):  NURI_PKCS11_MODE=sim pkcs11-tool --module dist/pkcs11-nuri.so -L / -O / --sign -m ECDSA
 * Real card:            NURI_PKCS11_MODE=card pkcs11-tool --module dist/pkcs11-nuri.so ...
 * Helper lookup: $NURI_PKCS11_HELPER, else <dir of this .so>/../scripts/pkcs11-helper.py.
 * Python: $NURI_PKCS11_PYTHON, else python3 (needs ecdsa; pyscard for card mode).
 * ETH2 PIN sessions are not implemented: login/sign fail closed. ETH1 is demo-only.
 */

#define _DARWIN_C_SOURCE
#define _GNU_SOURCE   /* asprintf, dladdr on glibc (Linux build UNVERIFIED) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>

/* PKCS#11 types */
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_SLOT_ID;
typedef unsigned long CK_OBJECT_HANDLE;
typedef unsigned char CK_BYTE;
typedef unsigned char CK_BBOOL;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_ULONG CK_FLAGS;
typedef CK_ULONG CK_SLOT_INFO_FLAGS;

#define CK_TRUE 1
#define CK_FALSE 0
#define CKR_OK 0x00000000
#define CKR_GENERAL_ERROR 0x00000001
#define CKR_FUNCTION_FAILED 0x00000006
#define CKR_ARGUMENTS_BAD 0x00000007
#define CKR_TOKEN_NOT_PRESENT 0x000000E0
#define CKR_SLOT_ID_INVALID 0x00000003
#define CKR_SESSION_HANDLE_INVALID 0x000000B3
#define CKR_OBJECT_HANDLE_INVALID 0x00000082
#define CKR_MECHANISM_INVALID 0x00000070
#define CKR_DEVICE_ERROR 0x00000030
#define CKR_BUFFER_TOO_SMALL 0x00000150
#define CKR_ATTRIBUTE_TYPE_INVALID 0x00000012
#define CKR_USER_NOT_LOGGED_IN 0x00000101
#define CKR_DATA_LEN_RANGE 0x00000021
#define CKR_FUNCTION_NOT_SUPPORTED 0x00000054

#define CKO_PUBLIC_KEY 0x00000002
#define CKO_PRIVATE_KEY 0x00000003
#define CKK_EC 0x00000003
#define CKM_ECDSA 0x00001041
#define CKM_SHA256_RSA_PKCS 0x00000040

#define CKA_CLASS 0x00000000
#define CKA_TOKEN 0x00000001
#define CKA_PRIVATE 0x00000002
#define CKA_LABEL 0x00000003
#define CKA_KEY_TYPE 0x00000100
#define CKA_ID 0x00000102
#define CKA_EC_PARAMS 0x00000180
#define CKA_EC_POINT 0x00000181
#define CKA_SIGN 0x00000108
#define CKA_VERIFY 0x0000010A
#define CKA_MODIFIABLE 0x00000170
#define CKA_SENSITIVE 0x00000103
#define CKA_EXTRACTABLE 0x00000162
#define CKA_ALWAYS_AUTHENTICATE 0x00000202
#define CKA_ENCRYPT 0x00000104
#define CKA_WRAP 0x00000106
#define CKA_DECRYPT 0x00000105
#define CKA_UNWRAP 0x00000107
#define CKA_SIGN_RECOVER 0x00000109
#define CKA_VERIFY_RECOVER 0x0000010B
#define CKA_DERIVE 0x0000010C
#define CKA_LOCAL 0x00000163
#define CKA_NEVER_EXTRACTABLE 0x00000164
#define CKA_ALWAYS_SENSITIVE 0x00000165

#define CKF_TOKEN_PRESENT 0x00000001
#define CKF_RW_SESSION 0x00000002
#define CKF_SERIAL_SESSION 0x00000004
/* CK_TOKEN_INFO flags (different namespace from session flags) */
#define CKF_WRITE_PROTECTED 0x00000002
#define CKF_LOGIN_REQUIRED 0x00000004
#define CKF_TOKEN_INITIALIZED 0x00000400
/* CK_MECHANISM_INFO flags */
#define CKF_HW 0x00000001
#define CKF_SIGN 0x00000800
#define CKF_EC_F_P 0x00100000
#define CKF_EC_UNCOMPRESS 0x01000000
#define CKF_EC_COMPRESS 0x02000000
/* session states */
#define CKS_RO_PUBLIC_SESSION 0
#define CKS_RO_USER_FUNCTIONS 1

#define CKU_USER 0x00000001

/* secp256k1: DER OBJECT IDENTIFIER 1.3.132.0.10 */
static const CK_BYTE SECP256K1_OID_DER[] = {0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A};

typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

typedef struct CK_INFO {
    CK_VERSION cryptokiVersion;
    CK_BYTE manufacturerID[32];
    CK_ULONG flags;
    CK_BYTE libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;

typedef struct CK_SLOT_INFO {
    CK_BYTE slotDescription[64];
    CK_BYTE manufacturerID[32];
    CK_FLAGS flags;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
} CK_SLOT_INFO;

typedef struct CK_TOKEN_INFO {
    CK_BYTE label[32];
    CK_BYTE manufacturerID[32];
    CK_BYTE model[16];
    CK_BYTE serialNumber[16];
    CK_FLAGS flags;
    CK_ULONG ulMaxSessionCount;
    CK_ULONG ulSessionCount;
    CK_ULONG ulMaxRwSessionCount;
    CK_ULONG ulRwSessionCount;
    CK_ULONG ulMaxPinLen;
    CK_ULONG ulMinPinLen;
    CK_ULONG ulTotalPublicMemory;
    CK_ULONG ulFreePublicMemory;
    CK_ULONG ulTotalPrivateMemory;
    CK_ULONG ulFreePrivateMemory;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
    CK_BYTE utcTime[16];
} CK_TOKEN_INFO;

typedef struct CK_SESSION_INFO {
    CK_SLOT_ID slotID;
    CK_ULONG state;
    CK_FLAGS flags;
    CK_ULONG ulDeviceError;
} CK_SESSION_INFO;

typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_BYTE *pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    CK_BYTE *pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;

typedef struct CK_MECHANISM_INFO {
    CK_ULONG ulMinKeySize;
    CK_ULONG ulMaxKeySize;
    CK_FLAGS flags;
} CK_MECHANISM_INFO;

typedef struct CK_FUNCTION_LIST {
    CK_VERSION version;
    void *C_Initialize;
    void *C_Finalize;
    void *C_GetInfo;
    void *C_GetFunctionList;
    void *C_GetSlotList;
    void *C_GetSlotInfo;
    void *C_GetTokenInfo;
    void *C_GetMechanismList;
    void *C_GetMechanismInfo;
    void *C_InitToken;
    void *C_InitPIN;
    void *C_SetPIN;
    void *C_OpenSession;
    void *C_CloseSession;
    void *C_CloseAllSessions;
    void *C_GetSessionInfo;
    void *C_GetOperationState;
    void *C_SetOperationState;
    void *C_Login;
    void *C_Logout;
    void *C_CreateObject;
    void *C_CopyObject;
    void *C_DestroyObject;
    void *C_GetObjectSize;
    void *C_GetAttributeValue;
    void *C_SetAttributeValue;
    void *C_FindObjectsInit;
    void *C_FindObjects;
    void *C_FindObjectsFinal;
    void *C_EncryptInit;
    void *C_Encrypt;
    void *C_EncryptUpdate;
    void *C_EncryptFinal;
    void *C_DecryptInit;
    void *C_Decrypt;
    void *C_DecryptUpdate;
    void *C_DecryptFinal;
    void *C_DigestInit;
    void *C_Digest;
    void *C_DigestUpdate;
    void *C_DigestKey;
    void *C_DigestFinal;
    void *C_SignInit;
    void *C_Sign;
    void *C_SignUpdate;
    void *C_SignFinal;
    void *C_SignRecoverInit;
    void *C_SignRecover;
    void *C_VerifyInit;
    void *C_Verify;
    void *C_VerifyUpdate;
    void *C_VerifyFinal;
    void *C_VerifyRecoverInit;
    void *C_VerifyRecover;
    void *C_DigestEncryptUpdate;
    void *C_DecryptDigestUpdate;
    void *C_SignEncryptUpdate;
    void *C_DecryptVerifyUpdate;
    void *C_GenerateKey;
    void *C_GenerateKeyPair;
    void *C_WrapKey;
    void *C_UnwrapKey;
    void *C_DeriveKey;
    void *C_SeedRandom;
    void *C_GenerateRandom;
    void *C_GetFunctionStatus;
    void *C_CancelFunction;
    void *C_WaitForSlotEvent;
} CK_FUNCTION_LIST;

/* --- State --- */
static int initialized = 0;
static CK_SESSION_HANDLE next_session = 1;
static CK_SESSION_HANDLE open_session = 0;
static const CK_OBJECT_HANDLE priv_handle = 1;   /* CKO_PRIVATE_KEY */
static const CK_OBJECT_HANDLE pub_handle = 2;    /* CKO_PUBLIC_KEY */
static char key_pubkey[128] = {0};               /* 33-byte compressed point, hex */
static uint8_t key_point[65];                    /* 04||X||Y, filled by C_Initialize */
static size_t key_point_len = 0;
static int key_found = 0;
static int logged_in = 0;
static int sim_mode = 0;
static int pin_required = 1;
static char selected_applet[16] = {0};

static const char *object_label(void) {
    return sim_mode ? "Nuri SIMULATOR ETH Key" : "Nuri ETH Key";
}

static void padded(CK_BYTE *out, size_t size, const char *text) {
    memset(out, ' ', size);
    size_t n = strlen(text);
    memcpy(out, text, n < size ? n : size);
}
/* find state: which handles still to return for the current C_FindObjectsInit */
static int find_active = 0;
static int find_want_priv = 0, find_want_pub = 0;

/* --- Helper path --- */
#ifndef NURI_PKCS11_HELPER
#define NURI_PKCS11_HELPER "scripts/pkcs11-helper.py"
#endif
#ifndef NURI_PKCS11_PYTHON
#define NURI_PKCS11_PYTHON "python3"
#endif

static char *helper_path(void) {
    const char *env = getenv("NURI_PKCS11_HELPER");
    if (env && *env) return strdup(env);
    /* Default: <dir of this .so>/../scripts/pkcs11-helper.py, so the module works
     * from any cwd when loaded from dist/. Falls back to the relative default. */
    Dl_info info;
    if (dladdr((void *)helper_path, &info) && info.dli_fname) {
        const char *slash = strrchr(info.dli_fname, '/');
        if (slash) {
            size_t dirlen = (size_t)(slash - info.dli_fname);
            char *out = NULL;
            if (asprintf(&out, "%.*s/../scripts/pkcs11-helper.py", (int)dirlen, info.dli_fname) != -1 &&
                access(out, R_OK) == 0)
                return out;
            free(out);
        }
    }
    return strdup(NURI_PKCS11_HELPER);
}

static char *python_path(void) {
    const char *env = getenv("NURI_PKCS11_PYTHON");
    return strdup((env && *env) ? env : NURI_PKCS11_PYTHON);
}

static char *shell_quote(const char *s) {
    size_t len = 3;
    for (const char *p = s; *p; p++) len += (*p == '\'') ? 4 : 1;
    char *out = malloc(len);
    if (!out) return NULL;
    char *q = out;
    *q++ = '\'';
    for (const char *p = s; *p; p++) {
        if (*p == '\'') { memcpy(q, "'\\''", 4); q += 4; }
        else *q++ = *p;
    }
    *q++ = '\'';
    *q = '\0';
    return out;
}

static char *hex_encode(const uint8_t *buf, size_t len) {
    static const char hex[] = "0123456789abcdef";
    char *out = malloc(len * 2 + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < len; i++) {
        out[i*2] = hex[buf[i] >> 4];
        out[i*2+1] = hex[buf[i] & 15];
    }
    out[len*2] = '\0';
    return out;
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
            while (value_len > 0 && (value[value_len-1] == '\r' || value[value_len-1] == '\n')) value_len--;
            char *out = malloc(value_len + 1);
            if (!out) return NULL;
            memcpy(out, value, value_len);
            out[value_len] = '\0';
            return out;
        }
        p = end ? end + 1 : line + line_len;
    }
    return NULL;
}

static char *run_helper(const char *input) {
    /* Use temp file for input */
    const char *tmpdir = getenv("TMPDIR");
    char *tmp_in = NULL;
    if (asprintf(&tmp_in, "%s/nuri-pkcs11-in-XXXXXX", (tmpdir && *tmpdir) ? tmpdir : "/tmp") < 0) return NULL;
    int fd_in = mkstemp(tmp_in);
    if (fd_in < 0) { free(tmp_in); return NULL; }
    size_t input_len = strlen(input);
    ssize_t written = write(fd_in, input, input_len);
    close(fd_in);
    if (written < 0 || (size_t)written != input_len) { unlink(tmp_in); free(tmp_in); return NULL; }

    char *python3 = python_path(), *helper3 = helper_path();
    char *pq = shell_quote(python3), *hq = shell_quote(helper3);
    char *run_cmd = NULL;
    /* C_Initialize freezes the selected mode. The helper also rejects conflicts. */
    const char *flag = sim_mode ? "--sim" : "--card";
    char *tq = shell_quote(tmp_in);
    asprintf(&run_cmd, "%s %s %s < %s", pq, hq, flag, tq);
    free(tq);
    free(pq); free(hq); free(python3); free(helper3);

    FILE *fp = popen(run_cmd, "r");
    free(run_cmd);
    if (!fp) { unlink(tmp_in); free(tmp_in); return NULL; }

    size_t cap = 4096, len = 0;
    char *out = malloc(cap);
    if (!out) { pclose(fp); unlink(tmp_in); free(tmp_in); return NULL; }
    out[0] = '\0';
    char chunk[1024];
    while (fgets(chunk, sizeof(chunk), fp)) {
        size_t n = strlen(chunk);
        if (len + n + 1 > cap) {
            cap = (len + n + 1) * 2;
            char *tmp = realloc(out, cap);
            if (!tmp) { free(out); pclose(fp); unlink(tmp_in); free(tmp_in); return NULL; }
            out = tmp;
        }
        memcpy(out + len, chunk, n);
        len += n;
        out[len] = '\0';
    }
    int status = pclose(fp);
    unlink(tmp_in);
    free(tmp_in);
    char *mode = value_for(out, "mode");
    char *error = value_for(out, "error");
    char *applet = value_for(out, "applet");
    int valid = status == 0 && !error && mode &&
        strcmp(mode, sim_mode ? "sim" : "card") == 0 &&
        (!selected_applet[0] || (applet && strcmp(applet, selected_applet) == 0));
    free(mode); free(error); free(applet);
    if (!valid) { free(out); return NULL; }
    return out;
}


/* --- secp256k1 point decompression (fixed 256-bit arithmetic, no deps) ---
 * The card/helper reports a 33-byte compressed point; PKCS#11 consumers
 * (pkcs11-tool, OpenSSL) expect CKA_EC_POINT as DER OCTET STRING of the
 * uncompressed 04||X||Y point. y = sqrt(x^3 + 7) mod p, p = 3 mod 4 so
 * sqrt(a) = a^((p+1)/4). */
typedef struct { uint32_t w[8]; } u256;        /* little-endian words */
static const u256 SECP_P = {{0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
                             0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};

static int u256_cmp(const u256 *a, const u256 *b) {
    for (int i = 7; i >= 0; i--) {
        if (a->w[i] != b->w[i]) return a->w[i] > b->w[i] ? 1 : -1;
    }
    return 0;
}
static uint32_t u256_add(u256 *r, const u256 *a, const u256 *b) {
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) { c += (uint64_t)a->w[i] + b->w[i]; r->w[i] = (uint32_t)c; c >>= 32; }
    return (uint32_t)c;
}
static void u256_sub(u256 *r, const u256 *a, const u256 *b) {
    int64_t c = 0;
    for (int i = 0; i < 8; i++) { c += (int64_t)a->w[i] - b->w[i]; r->w[i] = (uint32_t)c; c >>= 32; }
}
static void mod_add(u256 *r, const u256 *a, const u256 *b) {
    uint32_t carry = u256_add(r, a, b);
    if (carry || u256_cmp(r, &SECP_P) >= 0) u256_sub(r, r, &SECP_P);
}
static void mod_mul(u256 *r, const u256 *a, const u256 *b) {
    /* schoolbook 512-bit product, then reduce with p = 2^256 - c, c = 2^32 + 977 */
    uint32_t t[16] = {0};
    for (int i = 0; i < 8; i++) {
        uint64_t c = 0;
        for (int j = 0; j < 8; j++) {
            c += (uint64_t)a->w[i] * b->w[j] + t[i + j];
            t[i + j] = (uint32_t)c; c >>= 32;
        }
        t[i + 8] = (uint32_t)c;
    }
    /* fold high half: hi * 2^256 == hi * c (mod p); repeat until it fits */
    for (int round = 0; round < 3; round++) {
        uint32_t hi[8]; memcpy(hi, t + 8, 32); memset(t + 8, 0, 32);
        uint64_t c977 = 0, c32 = 0;
        for (int i = 0; i < 8; i++) {
            c977 += (uint64_t)hi[i] * 977 + t[i];
            t[i] = (uint32_t)c977; c977 >>= 32;
        }
        t[8] = (uint32_t)c977;
        for (int i = 0; i < 8; i++) {
            c32 += (uint64_t)hi[i] + t[i + 1];
            t[i + 1] = (uint32_t)c32; c32 >>= 32;
        }
        t[9] = (uint32_t)c32;
    }
    memcpy(r->w, t, 32);
    while (u256_cmp(r, &SECP_P) >= 0) u256_sub(r, r, &SECP_P);
}
static void mod_pow(u256 *r, const u256 *base, const u256 *exp) {
    u256 acc = {{1,0,0,0,0,0,0,0}}, b = *base;
    for (int i = 0; i < 256; i++) {
        if ((exp->w[i / 32] >> (i % 32)) & 1) mod_mul(&acc, &acc, &b);
        mod_mul(&b, &b, &b);
    }
    *r = acc;
}
static void u256_from_be(u256 *r, const uint8_t *be) {
    for (int i = 0; i < 8; i++)
        r->w[7 - i] = ((uint32_t)be[i*4] << 24) | ((uint32_t)be[i*4+1] << 16) | ((uint32_t)be[i*4+2] << 8) | be[i*4+3];
}
static void u256_to_be(uint8_t *be, const u256 *a) {
    for (int i = 0; i < 8; i++) {
        uint32_t w = a->w[7 - i];
        be[i*4] = w >> 24; be[i*4+1] = w >> 16; be[i*4+2] = w >> 8; be[i*4+3] = w;
    }
}
/* in: 33-byte compressed point; out: 65-byte 04||X||Y. Returns 0 on success. */
static int secp256k1_decompress(const uint8_t *in, uint8_t *out) {
    if (in[0] != 0x02 && in[0] != 0x03) return -1;
    u256 x, y, t, seven = {{7,0,0,0,0,0,0,0}};
    u256_from_be(&x, in + 1);
    if (u256_cmp(&x, &SECP_P) >= 0) return -1;
    mod_mul(&t, &x, &x); mod_mul(&t, &t, &x); mod_add(&t, &t, &seven);   /* x^3 + 7 */
    u256 e = SECP_P; e.w[0] += 1;                                        /* p + 1 (no carry: low word is ...FC2F) */
    for (int i = 0; i < 8; i++) { e.w[i] >>= 2; if (i < 7) e.w[i] |= e.w[i+1] << 30; } /* (p+1)/4 */
    mod_pow(&y, &t, &e);
    u256 y2; mod_mul(&y2, &y, &y);
    if (u256_cmp(&y2, &t) != 0) return -1;                               /* not on curve */
    if ((y.w[0] & 1) != (uint32_t)(in[0] & 1)) u256_sub(&y, &SECP_P, &y);
    out[0] = 0x04; u256_to_be(out + 1, &x); u256_to_be(out + 33, &y);
    return 0;
}

static int hex_decode(const char *hex, uint8_t *out, size_t out_max) {
    size_t n = strlen(hex);
    if (n % 2 || n / 2 > out_max) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int v = 0;
        for (int k = 0; k < 2; k++) {
            char c = hex[i*2+k];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= c - '0';
            else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
            else return -1;
        }
        out[i] = (uint8_t)v;
    }
    return (int)(n / 2);
}

/* --- PKCS#11 Functions --- */

static CK_RV C_Initialize(void *pInitArgs) {
    (void)pInitArgs;
    if (initialized) return CKR_OK;

    const char *mode = getenv("NURI_PKCS11_MODE");
    if (mode && strcmp(mode, "card") != 0 && strcmp(mode, "sim") != 0) {
        fprintf(stderr, "NURI_PKCS11_MODE must be exactly card or sim (unset means card)\n");
        return CKR_ARGUMENTS_BAD;
    }
    sim_mode = mode && strcmp(mode, "sim") == 0;
    key_found = 0; key_point_len = 0; key_pubkey[0] = 0;
    pin_required = 1; selected_applet[0] = 0;
    if (sim_mode) fprintf(stderr, "WARNING: SIMULATOR: deterministic software key, NOT hardware\n");
    /* Run helper to init and find key */
    char *out = run_helper("INIT\nSLOTS\nOPEN_SESSION\nFIND_KEY\nCLOSE_SESSION\nFINALIZE\n");
    if (!out) return CKR_DEVICE_ERROR;

    char *applet = value_for(out, "applet");
    char *pin = value_for(out, "pin_required");
    const char *demo = getenv("NURI_ALLOW_ETH1_DEMO");
    int valid = applet && pin &&
        ((sim_mode && strcmp(applet, "SIMULATOR") == 0 && strcmp(pin, "0") == 0) ||
         (!sim_mode && strcmp(applet, "ETH2") == 0 && strcmp(pin, "1") == 0) ||
         (!sim_mode && strcmp(applet, "ETH1") == 0 && strcmp(pin, "0") == 0 && demo && strcmp(demo, "1") == 0));
    if (!valid) { free(applet); free(pin); free(out); return CKR_DEVICE_ERROR; }
    snprintf(selected_applet, sizeof(selected_applet), "%s", applet);
    pin_required = strcmp(pin, "1") == 0;
    free(applet); free(pin);
    char *pk = value_for(out, "key_pubkey");
    if (pk) {
        strncpy(key_pubkey, pk, sizeof(key_pubkey) - 1);
        uint8_t raw[65];
        int n = hex_decode(pk, raw, sizeof(raw));
        key_point_len = 0;
        if (n == 33 && secp256k1_decompress(raw, key_point) == 0) key_point_len = 65;
        key_found = (key_point_len == 65);
        free(pk);
    }
    free(out);

    if (!key_found) { selected_applet[0] = 0; return CKR_DEVICE_ERROR; }
    initialized = 1;
    return CKR_OK;
}

static CK_RV C_Finalize(void *pReserved) {
    (void)pReserved;
    initialized = 0;
    key_found = 0; key_point_len = 0; key_pubkey[0] = 0;
    selected_applet[0] = 0; pin_required = 1;
    find_want_priv = find_want_pub = 0;
    open_session = 0;
    logged_in = 0;
    find_active = 0;
    return CKR_OK;
}

static CK_RV C_GetInfo(CK_INFO *pInfo) {
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    memcpy(pInfo->manufacturerID, "Nuri.com                        ", 32);
    pInfo->flags = 0;
    memcpy(pInfo->libraryDescription, "Nuri Smartcard PKCS#11           ", 32);
    pInfo->libraryVersion.major = 1;
    pInfo->libraryVersion.minor = 0;
    return CKR_OK;
}

static CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID *pSlotList, CK_ULONG *pulCount) {
    (void)tokenPresent;
    if (!pulCount) return CKR_ARGUMENTS_BAD;
    if (pSlotList) {
        if (*pulCount < 1) return CKR_BUFFER_TOO_SMALL;
        pSlotList[0] = 1;
    }
    *pulCount = 1;
    return CKR_OK;
}

static CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO *pInfo) {
    if (slotID != 1) return CKR_SLOT_ID_INVALID;
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    memset(pInfo, 0, sizeof(*pInfo));
    padded(pInfo->slotDescription, sizeof(pInfo->slotDescription), sim_mode ? "Nuri SIMULATOR (software)" : "Nuri Smartcard (PC/SC)");
    memcpy(pInfo->manufacturerID, "Nuri.com                        ", 32);
    pInfo->flags = CKF_TOKEN_PRESENT;
    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 3;
    return CKR_OK;
}

static CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO *pInfo) {
    if (slotID != 1) return CKR_SLOT_ID_INVALID;
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    memset(pInfo, 0, sizeof(*pInfo));
    padded(pInfo->label, sizeof(pInfo->label), sim_mode ? "Nuri SIMULATOR" : "Nuri Smartcard");
    memcpy(pInfo->manufacturerID, "Nuri.com                        ", 32);
    padded(pInfo->model, sizeof(pInfo->model), selected_applet);
    memcpy(pInfo->serialNumber, "0000000000000000", 16);
    /* Do not claim login can authenticate an ETH2 process-per-operation bridge. */
    pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED | (pin_required ? CKF_LOGIN_REQUIRED : 0);
    pInfo->ulMaxSessionCount = 1;
    pInfo->ulSessionCount = 0;
    pInfo->ulMaxRwSessionCount = 1;
    pInfo->ulRwSessionCount = 0;
    pInfo->ulMaxPinLen = pin_required ? 16 : 0;
    pInfo->ulMinPinLen = pin_required ? 4 : 0;
    pInfo->ulTotalPublicMemory = 1024;
    pInfo->ulFreePublicMemory = 1024;
    pInfo->ulTotalPrivateMemory = 1024;
    pInfo->ulFreePrivateMemory = 1024;
    pInfo->hardwareVersion.major = 1;
    pInfo->hardwareVersion.minor = 0;
    pInfo->firmwareVersion.major = 1;
    pInfo->firmwareVersion.minor = 3;
    return CKR_OK;
}

static CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, void *pApplication, void *Notify, CK_SESSION_HANDLE *phSession) {
    (void)pApplication; (void)Notify; (void)flags;
    if (slotID != 1) return CKR_SLOT_ID_INVALID;
    if (!phSession) return CKR_ARGUMENTS_BAD;
    *phSession = next_session++;
    open_session = *phSession;
    return CKR_OK;
}

static CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    if (hSession != open_session) return CKR_SESSION_HANDLE_INVALID;
    open_session = 0;
    logged_in = 0;
    return CKR_OK;
}

static CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
    if (slotID != 1) return CKR_SLOT_ID_INVALID;
    open_session = 0;
    logged_in = 0;
    return CKR_OK;
}

static CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO *pInfo) {
    if (hSession != open_session) return CKR_SESSION_HANDLE_INVALID;
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    pInfo->slotID = 1;
    pInfo->state = logged_in ? CKS_RO_USER_FUNCTIONS : CKS_RO_PUBLIC_SESSION;
    pInfo->flags = CKF_SERIAL_SESSION;
    pInfo->ulDeviceError = 0;
    return CKR_OK;
}

/* ETH2 requires a real authenticated card session; none is implemented here.
 * In sim / explicitly armed ETH1 demo only, login does not authenticate a PIN. */
static CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_ULONG userType, CK_BYTE *pPin, CK_ULONG ulPinLen) {
    (void)userType; (void)pPin; (void)ulPinLen;
    if (hSession != open_session) return CKR_SESSION_HANDLE_INVALID;
    if (pin_required) {
        fprintf(stderr, "ETH2 PIN required: PKCS#11 authenticated PIN sessions not implemented\n");
        return CKR_USER_NOT_LOGGED_IN;
    }
    logged_in = 1;
    return CKR_OK;
}

static CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
    if (hSession != open_session) return CKR_SESSION_HANDLE_INVALID;
    logged_in = 0;
    return CKR_OK;
}

/* Copy one attribute value per PKCS#11 v2.40 §5.2 semantics. */
static CK_RV put_attr(CK_ATTRIBUTE *a, const void *val, CK_ULONG len) {
    if (a->pValue) {
        if (a->ulValueLen < len) { a->ulValueLen = (CK_ULONG)-1; return CKR_BUFFER_TOO_SMALL; }
        memcpy(a->pValue, val, len);
    }
    a->ulValueLen = len;
    return CKR_OK;
}

static CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount) {
    (void)hSession;
    if (hObject != priv_handle && hObject != pub_handle) return CKR_OBJECT_HANDLE_INVALID;
    if (!pTemplate) return CKR_ARGUMENTS_BAD;
    const int is_priv = (hObject == priv_handle);
    const CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CK_RV rv = CKR_OK;

    for (CK_ULONG i = 0; i < ulCount; i++) {
        CK_ATTRIBUTE *a = &pTemplate[i];
        CK_RV r = CKR_OK;
        switch (a->type) {
        case CKA_CLASS: {
            CK_OBJECT_CLASS cls = is_priv ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
            r = put_attr(a, &cls, sizeof(cls)); break;
        }
        case CKA_KEY_TYPE: {
            CK_KEY_TYPE kt = CKK_EC;
            r = put_attr(a, &kt, sizeof(kt)); break;
        }
        case CKA_LABEL:    r = put_attr(a, object_label(), strlen(object_label())); break;
        case CKA_ID:       r = put_attr(a, "\x01", 1); break;
        case CKA_TOKEN:    r = put_attr(a, &t, 1); break;
        case CKA_PRIVATE:  r = put_attr(a, is_priv ? &t : &f, 1); break;
        case CKA_MODIFIABLE: r = put_attr(a, &f, 1); break;
        case CKA_SIGN:     r = put_attr(a, is_priv ? &t : &f, 1); break;
        case CKA_VERIFY:   r = put_attr(a, is_priv ? &f : &t, 1); break;
        case CKA_SENSITIVE: r = put_attr(a, is_priv ? &t : &f, 1); break;
        case CKA_EXTRACTABLE: r = put_attr(a, &f, 1); break;
        case CKA_NEVER_EXTRACTABLE: r = put_attr(a, &t, 1); break;
        case CKA_ALWAYS_SENSITIVE: r = put_attr(a, is_priv ? &t : &f, 1); break;
        case CKA_LOCAL:    r = put_attr(a, sim_mode ? &f : &t, 1); break;
        case CKA_ENCRYPT: case CKA_DECRYPT: case CKA_WRAP: case CKA_UNWRAP:
        case CKA_SIGN_RECOVER: case CKA_VERIFY_RECOVER: case CKA_DERIVE:
            r = put_attr(a, &f, 1); break;
        case CKA_ALWAYS_AUTHENTICATE: r = put_attr(a, is_priv && pin_required ? &t : &f, 1); break;
        case CKA_EC_PARAMS:
            r = put_attr(a, SECP256K1_OID_DER, sizeof(SECP256K1_OID_DER)); break;
        case CKA_EC_POINT: {
            /* DER OCTET STRING { 04 || X || Y } = 04 41 04 X Y (67 bytes) */
            if (key_point_len != 65) { a->ulValueLen = (CK_ULONG)-1; r = CKR_ATTRIBUTE_TYPE_INVALID; break; }
            uint8_t der[67]; der[0] = 0x04; der[1] = 0x41; memcpy(der + 2, key_point, 65);
            r = put_attr(a, der, sizeof(der)); break;
        }
        default:
            a->ulValueLen = (CK_ULONG)-1;
            r = CKR_ATTRIBUTE_TYPE_INVALID;
            break;
        }
        if (r != CKR_OK) rv = r;   /* keep filling the rest, report the last error (spec) */
    }
    return rv;
}

static CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount) {
    (void)hSession;
    /* Honour CKA_CLASS and CKA_ID in the template; anything else matches. */
    find_want_priv = find_want_pub = key_found;
    for (CK_ULONG i = 0; i < ulCount && pTemplate; i++) {
        CK_ATTRIBUTE *a = &pTemplate[i];
        if (a->type == CKA_CLASS && a->pValue && a->ulValueLen == sizeof(CK_OBJECT_CLASS)) {
            CK_OBJECT_CLASS cls; memcpy(&cls, a->pValue, sizeof(cls));
            if (cls != CKO_PRIVATE_KEY) find_want_priv = 0;
            if (cls != CKO_PUBLIC_KEY) find_want_pub = 0;
        } else if (a->type == CKA_ID && a->pValue) {
            if (!(a->ulValueLen == 1 && ((CK_BYTE *)a->pValue)[0] == 1)) find_want_priv = find_want_pub = 0;
        } else if (a->type == CKA_LABEL && a->pValue) {
            if (!(a->ulValueLen == strlen(object_label()) && memcmp(a->pValue, object_label(), a->ulValueLen) == 0)) find_want_priv = find_want_pub = 0;
        }
    }
    find_active = 1;
    return CKR_OK;
}

static CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE *phObject, CK_ULONG ulMaxObjectCount, CK_ULONG *pulObjectCount) {
    (void)hSession;
    if (!phObject || !pulObjectCount) return CKR_ARGUMENTS_BAD;
    CK_ULONG n = 0;
    if (find_active && n < ulMaxObjectCount && find_want_priv) { phObject[n++] = priv_handle; find_want_priv = 0; }
    if (find_active && n < ulMaxObjectCount && find_want_pub)  { phObject[n++] = pub_handle;  find_want_pub = 0; }
    *pulObjectCount = n;   /* returns 0 once exhausted: the enumeration terminates */
    return CKR_OK;
}

static CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
    (void)hSession;
    find_active = 0;
    return CKR_OK;
}

static CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey) {
    (void)hSession;
    if (!pMechanism) return CKR_ARGUMENTS_BAD;
    if (pMechanism->mechanism != CKM_ECDSA) return CKR_MECHANISM_INVALID;
    if (hKey != priv_handle) return CKR_OBJECT_HANDLE_INVALID;
    if (pin_required) return CKR_USER_NOT_LOGGED_IN;
    return CKR_OK;
}

static CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE *pData, CK_ULONG ulDataLen, CK_BYTE *pSignature, CK_ULONG *pulSignatureLen) {
    (void)hSession;
    if (!pData || !pulSignatureLen) return CKR_ARGUMENTS_BAD;
    if (!initialized || !key_found) return CKR_DEVICE_ERROR;
    if (pin_required) return CKR_USER_NOT_LOGGED_IN;
    /* The ETH applet signs exactly one 32-byte digest (INS 04, Lc=0x20). */
    if (ulDataLen != 32) return CKR_DATA_LEN_RANGE;
    if (!pSignature) { *pulSignatureLen = 64; return CKR_OK; }   /* size query: no card round-trip */

    char *hash_hex = hex_encode(pData, ulDataLen);
    if (!hash_hex) return CKR_DEVICE_ERROR;

    char input[256];
    snprintf(input, sizeof(input), "INIT\nOPEN_SESSION\nSIGN %s\nCLOSE_SESSION\nFINALIZE\n", hash_hex);
    free(hash_hex);

    char *out = run_helper(input);
    if (!out) return CKR_DEVICE_ERROR;

    char *sig_hex = value_for(out, "signature");
    free(out);

    if (!sig_hex) return CKR_FUNCTION_FAILED;

    uint8_t decoded[64];
    if (strlen(sig_hex) != 128 || hex_decode(sig_hex, decoded, sizeof(decoded)) != 64) {
        free(sig_hex); return CKR_FUNCTION_FAILED;
    }
    size_t sig_len = sizeof(decoded);

    if (pSignature) {
        if (*pulSignatureLen < sig_len) { free(sig_hex); return CKR_BUFFER_TOO_SMALL; }
        memcpy(pSignature, decoded, sig_len);
    }
    *pulSignatureLen = sig_len;
    free(sig_hex);
    return CKR_OK;
}

static CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE *pMechanismList, CK_ULONG *pulCount) {
    if (slotID != 1) return CKR_SLOT_ID_INVALID;
    if (!pulCount) return CKR_ARGUMENTS_BAD;
    if (pMechanismList) {
        if (*pulCount < 1) return CKR_BUFFER_TOO_SMALL;
        pMechanismList[0] = CKM_ECDSA;
    }
    *pulCount = 1;
    return CKR_OK;
}

/* pkcs11-tool falls back to C_SignUpdate/C_SignFinal when C_Sign fails and
 * dereferences the function pointers unconditionally, so they must exist. The
 * applet has no streaming interface: one 32-byte digest per C_Sign. */
static CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE *pPart, CK_ULONG ulPartLen) {
    (void)hSession; (void)pPart; (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}
static CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE *pSignature, CK_ULONG *pulSignatureLen) {
    (void)hSession; (void)pSignature; (void)pulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO *pInfo) {
    if (slotID != 1) return CKR_SLOT_ID_INVALID;
    if (type != CKM_ECDSA) return CKR_MECHANISM_INVALID;
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    pInfo->ulMinKeySize = 256;
    pInfo->ulMaxKeySize = 256;
    pInfo->flags = (sim_mode ? 0 : CKF_HW) | CKF_SIGN | CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS;
    return CKR_OK;
}

/* --- Function list --- */
static CK_FUNCTION_LIST function_list = {
    {2, 40},
    C_Initialize, C_Finalize, C_GetInfo, NULL /*C_GetFunctionList*/, C_GetSlotList,
    C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList, C_GetMechanismInfo,
    NULL /*InitToken*/, NULL /*InitPIN*/, NULL /*SetPIN*/, C_OpenSession, C_CloseSession,
    C_CloseAllSessions, C_GetSessionInfo, NULL /*GetOperationState*/, NULL /*SetOperationState*/, C_Login, C_Logout,
    NULL /*CreateObject*/, NULL /*CopyObject*/, NULL /*DestroyObject*/, NULL /*GetObjectSize*/, C_GetAttributeValue,
    NULL /*SetAttributeValue*/, C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal,
    NULL, NULL, NULL, NULL, /* Encrypt* */
    NULL, NULL, NULL, NULL, /* Decrypt* */
    NULL, NULL, NULL, NULL, NULL, /* Digest* */
    C_SignInit, C_Sign, C_SignUpdate, C_SignFinal, NULL /*SignRecoverInit*/, NULL /*SignRecover*/,
    NULL, NULL, NULL, NULL, NULL, NULL, /* Verify* */
    NULL, NULL, NULL, NULL, /* DigestEncryptUpdate .. DecryptVerifyUpdate */
    NULL, NULL, NULL, NULL, NULL, /* GenerateKey, GenerateKeyPair, WrapKey, UnwrapKey, DeriveKey */
    NULL, NULL, /* SeedRandom, GenerateRandom */
    NULL, NULL, NULL, /* GetFunctionStatus, CancelFunction, WaitForSlotEvent */
};

__attribute__((visibility("default")))
CK_RV C_GetFunctionList(CK_FUNCTION_LIST **ppFunctionList) {
    if (!ppFunctionList) return CKR_ARGUMENTS_BAD;
    *ppFunctionList = &function_list;
    return CKR_OK;
}
