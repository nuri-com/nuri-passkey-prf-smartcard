/* pkcs11-nuri.c — Minimal PKCS#11 module for Nuri smartcard.
 * Delegates signing to scripts/pkcs11-helper.py over stdin/stdout.
 * 
 * Build: clang -dynamiclib -fvisibility=hidden -Wall -O2 \
 *   -o dist/pkcs11-nuri.so scripts/pkcs11-nuri.c
 *
 * Test: pkcs11-tool --module dist/pkcs11-nuri.so -O
 *       openssl dgst -sha256 -sign dist/pkcs11-nuri.so -out sig.bin data.txt
 */

#define _DARWIN_C_SOURCE
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
#define CKA_EC_POINT 0x00000181
#define CKA_SIGN 0x00000108
#define CKA_VERIFY 0x0000010A

#define CKF_TOKEN_PRESENT 0x00000001
#define CKF_RW_SESSION 0x00000002
#define CKF_SERIAL_SESSION 0x00000004

#define CKU_USER 0x00000001

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
static CK_OBJECT_HANDLE key_handle = 1;
static char key_pubkey[128] = {0};
static int key_found = 0;

/* --- Helper path --- */
#ifndef NURI_PKCS11_HELPER
#define NURI_PKCS11_HELPER "scripts/pkcs11-helper.py"
#endif
#ifndef NURI_PKCS11_PYTHON
#define NURI_PKCS11_PYTHON "python3"
#endif

static char *helper_path(void) {
    const char *env = getenv("NURI_PKCS11_HELPER");
    return strdup((env && *env) ? env : NURI_PKCS11_HELPER);
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
    char tmp_in[] = "/tmp/nuri-pkcs11-in-XXXXXX";
    int fd_in = mkstemp(tmp_in);
    if (fd_in < 0) return NULL;
    write(fd_in, input, strlen(input));
    close(fd_in);

    char *python3 = python_path(), *helper3 = helper_path();
    char *pq = shell_quote(python3), *hq = shell_quote(helper3);
    char *run_cmd = NULL;
    asprintf(&run_cmd, "%s %s --sim < %s", pq, hq, tmp_in);
    free(pq); free(hq); free(python3); free(helper3);

    FILE *fp = popen(run_cmd, "r");
    free(run_cmd);
    if (!fp) { unlink(tmp_in); return NULL; }

    size_t cap = 4096, len = 0;
    char *out = malloc(cap);
    if (!out) { pclose(fp); unlink(tmp_in); return NULL; }
    out[0] = '\0';
    char chunk[1024];
    while (fgets(chunk, sizeof(chunk), fp)) {
        size_t n = strlen(chunk);
        if (len + n + 1 > cap) {
            cap = (len + n + 1) * 2;
            char *tmp = realloc(out, cap);
            if (!tmp) { free(out); pclose(fp); unlink(tmp_in); return NULL; }
            out = tmp;
        }
        memcpy(out + len, chunk, n);
        len += n;
        out[len] = '\0';
    }
    pclose(fp);
    unlink(tmp_in);
    return out;
}

/* --- PKCS#11 Functions --- */

static CK_RV C_Initialize(void *pInitArgs) {
    (void)pInitArgs;
    if (initialized) return CKR_OK;

    /* Run helper to init and find key */
    char *out = run_helper("INIT\nSLOTS\nOPEN_SESSION\nFIND_KEY\nCLOSE_SESSION\nFINALIZE\n");
    if (!out) return CKR_DEVICE_ERROR;

    char *pk = value_for(out, "key_pubkey");
    if (pk) {
        strncpy(key_pubkey, pk, sizeof(key_pubkey) - 1);
        key_found = 1;
        free(pk);
    }
    free(out);

    initialized = 1;
    return CKR_OK;
}

static CK_RV C_Finalize(void *pReserved) {
    (void)pReserved;
    initialized = 0;
    open_session = 0;
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
    memcpy(pInfo->slotDescription, "Nuri Smartcard (PC/SC)          ", 64);
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
    memcpy(pInfo->label, "Nuri Smartcard                  ", 32);
    memcpy(pInfo->manufacturerID, "Nuri.com                        ", 32);
    memcpy(pInfo->model, "ETH v1.3        ", 16);
    memcpy(pInfo->serialNumber, "0000000000000000", 16);
    pInfo->flags = CKF_TOKEN_PRESENT | CKF_RW_SESSION;
    pInfo->ulMaxSessionCount = 1;
    pInfo->ulSessionCount = 0;
    pInfo->ulMaxRwSessionCount = 1;
    pInfo->ulRwSessionCount = 0;
    pInfo->ulMaxPinLen = 0;
    pInfo->ulMinPinLen = 0;
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
    (void)pApplication; (void)Notify;
    if (slotID != 1) return CKR_SLOT_ID_INVALID;
    if (!phSession) return CKR_ARGUMENTS_BAD;
    *phSession = next_session++;
    open_session = *phSession;
    return CKR_OK;
}

static CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    if (hSession != open_session) return CKR_SESSION_HANDLE_INVALID;
    open_session = 0;
    return CKR_OK;
}

static CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount) {
    (void)hSession;
    if (hObject != key_handle) return CKR_OBJECT_HANDLE_INVALID;
    if (!pTemplate) return CKR_ARGUMENTS_BAD;

    for (CK_ULONG i = 0; i < ulCount; i++) {
        switch (pTemplate[i].type) {
        case CKA_CLASS: {
            CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
            if (pTemplate[i].pValue) {
                if (pTemplate[i].ulValueLen < sizeof(cls)) return CKR_BUFFER_TOO_SMALL;
                memcpy(pTemplate[i].pValue, &cls, sizeof(cls));
            }
            pTemplate[i].ulValueLen = sizeof(cls);
            break;
        }
        case CKA_KEY_TYPE: {
            CK_KEY_TYPE kt = CKK_EC;
            if (pTemplate[i].pValue) {
                if (pTemplate[i].ulValueLen < sizeof(kt)) return CKR_BUFFER_TOO_SMALL;
                memcpy(pTemplate[i].pValue, &kt, sizeof(kt));
            }
            pTemplate[i].ulValueLen = sizeof(kt);
            break;
        }
        case CKA_SIGN:
            pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
            if (pTemplate[i].pValue) {
                if (pTemplate[i].ulValueLen < sizeof(CK_BBOOL)) return CKR_BUFFER_TOO_SMALL;
                *(CK_BBOOL*)pTemplate[i].pValue = CK_TRUE;
            }
            break;
        case CKA_LABEL:
            if (pTemplate[i].pValue) {
                size_t n = pTemplate[i].ulValueLen < 20 ? pTemplate[i].ulValueLen : 20;
                memcpy(pTemplate[i].pValue, "Nuri ETH Key", n);
            }
            pTemplate[i].ulValueLen = 20;
            break;
        case CKA_ID:
            if (pTemplate[i].pValue) {
                if (pTemplate[i].ulValueLen >= 1) pTemplate[i].pValue[0] = 1;
            }
            pTemplate[i].ulValueLen = 1;
            break;
        case CKA_TOKEN:
            pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
            if (pTemplate[i].pValue) *(CK_BBOOL*)pTemplate[i].pValue = CK_TRUE;
            break;
        case CKA_PRIVATE:
            pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
            if (pTemplate[i].pValue) *(CK_BBOOL*)pTemplate[i].pValue = CK_TRUE;
            break;
        default:
            pTemplate[i].ulValueLen = (CK_ULONG)-1;
            break;
        }
    }
    return CKR_OK;
}

static CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount) {
    (void)hSession; (void)pTemplate; (void)ulCount;
    return CKR_OK;
}

static CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE *phObject, CK_ULONG ulMaxObjectCount, CK_ULONG *pulObjectCount) {
    (void)hSession;
    if (!phObject || !pulObjectCount) return CKR_ARGUMENTS_BAD;
    if (ulMaxObjectCount < 1) return CKR_ARGUMENTS_BAD;
    if (!key_found) { *pulObjectCount = 0; return CKR_OK; }
    phObject[0] = key_handle;
    *pulObjectCount = 1;
    return CKR_OK;
}

static CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
    (void)hSession;
    return CKR_OK;
}

static CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey) {
    (void)hSession;
    if (!pMechanism) return CKR_ARGUMENTS_BAD;
    if (pMechanism->mechanism != CKM_ECDSA) return CKR_MECHANISM_INVALID;
    if (hKey != key_handle) return CKR_OBJECT_HANDLE_INVALID;
    return CKR_OK;
}

static CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE *pData, CK_ULONG ulDataLen, CK_BYTE *pSignature, CK_ULONG *pulSignatureLen) {
    (void)hSession;
    if (!pData || !pulSignatureLen) return CKR_ARGUMENTS_BAD;

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

    size_t sig_hex_len = strlen(sig_hex);
    size_t sig_len = sig_hex_len / 2;

    if (pSignature) {
        if (*pulSignatureLen < sig_len) { free(sig_hex); return CKR_BUFFER_TOO_SMALL; }
        for (size_t i = 0; i < sig_len; i++) {
            char hi = sig_hex[i*2], lo = sig_hex[i*2+1];
            int hv_hi = (hi >= '0' && hi <= '9') ? hi-'0' : (hi >= 'a' && hi <= 'f') ? hi-'a'+10 : (hi >= 'A' && hi <= 'F') ? hi-'A'+10 : 0;
            int hv_lo = (lo >= '0' && lo <= '9') ? lo-'0' : (lo >= 'a' && lo <= 'f') ? lo-'a'+10 : (lo >= 'A' && lo <= 'F') ? lo-'A'+10 : 0;
            pSignature[i] = (hv_hi << 4) | hv_lo;
        }
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

/* --- Function list --- */
static CK_FUNCTION_LIST function_list = {
    {2, 40},
    C_Initialize, C_Finalize, C_GetInfo, NULL, C_GetSlotList,
    C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList, NULL,
    NULL, NULL, NULL, C_OpenSession, C_CloseSession,
    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, C_GetAttributeValue,
    NULL, C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    C_SignInit, C_Sign, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
};

__attribute__((visibility("default")))
CK_RV C_GetFunctionList(CK_FUNCTION_LIST **ppFunctionList) {
    if (!ppFunctionList) return CKR_ARGUMENTS_BAD;
    *ppFunctionList = &function_list;
    return CKR_OK;
}
