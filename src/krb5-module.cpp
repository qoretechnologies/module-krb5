/* -*- mode: c++; indent-tabs-mode: nil -*- */
/*
    krb5-module.cpp

    Qore Kerberos Module

    Copyright (C) 2026 Qore Technologies, s.r.o.

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.
*/

#include "krb5-module.h"
#include "QC_GssClientContext.h"
#include "QC_Krb5Context.h"
#include "QC_Krb5Credentials.h"
#include "QC_Krb5CredentialCache.h"
#include "QC_Krb5Keytab.h"
#include "QC_Krb5Principal.h"

#include <qore/QoreSandboxManager.h>

#include <cctype>
#include <cstdlib>
#include <ctime>

static QoreNamespace krb5ns("Qore::Krb5");

TypedHashDecl* hashdeclKrb5KeytabEntryInfo = nullptr;
TypedHashDecl* hashdeclKrb5CredentialsInfo = nullptr;

static void krb5_module_init(QoreModuleInitContext& ctx, ExceptionSink& xsink);
static void krb5_module_ns_init(QoreNamespace* rns, QoreNamespace* qns, ExceptionSink& xsink);
static void krb5_module_delete();

extern "C" DLLEXPORT void krb5_qore_module_desc(QoreModuleInfo& mod_info) {
    mod_info.name = "krb5";
    mod_info.version = PACKAGE_VERSION;
    mod_info.desc = "Kerberos 5 and GSSAPI module";
    mod_info.author = "Qore Technologies, s.r.o.";
    mod_info.url = "https://qore.org";
    mod_info.api_major = QORE_MODULE_API_MAJOR;
    mod_info.api_minor = QORE_MODULE_API_MINOR;
    mod_info.init = krb5_module_init;
    mod_info.ns_init = krb5_module_ns_init;
    mod_info.del = krb5_module_delete;
    mod_info.license = QL_MIT;
    mod_info.license_str = "MIT";
}

DLLLOCAL int krb5_raise_exception(ExceptionSink* xsink, krb5_context ctx, krb5_error_code rc,
        const char* err, const char* context) {
    const char* msg = ctx ? krb5_get_error_message(ctx, rc) : nullptr;
    if (msg) {
        xsink->raiseException(err, "%s: %s (%d)", context, msg, (int)rc);
        krb5_free_error_message(ctx, msg);
    } else {
        xsink->raiseException(err, "%s: error code %d", context, (int)rc);
    }
    return -1;
}

DLLLOCAL int gss_raise_exception(ExceptionSink* xsink, const char* err, OM_uint32 major, OM_uint32 minor,
        const char* context) {
    OM_uint32 msg_ctx = 0;
    OM_uint32 min_stat = 0;
    gss_buffer_desc status = GSS_C_EMPTY_BUFFER;
    std::string message;

    do {
        gss_display_status(&min_stat, major, GSS_C_GSS_CODE, GSS_C_NO_OID, &msg_ctx, &status);
        if (status.length) {
            if (!message.empty()) {
                message += "; ";
            }
            message.append(static_cast<const char*>(status.value), status.length);
            gss_release_buffer(&min_stat, &status);
        }
    } while (msg_ctx);

    msg_ctx = 0;
    do {
        gss_display_status(&min_stat, minor, GSS_C_MECH_CODE, GSS_C_NO_OID, &msg_ctx, &status);
        if (status.length) {
            if (!message.empty()) {
                message += "; ";
            }
            message.append(static_cast<const char*>(status.value), status.length);
            gss_release_buffer(&min_stat, &status);
        }
    } while (msg_ctx);

    if (message.empty()) {
        message = "unknown GSSAPI error";
    }

    xsink->raiseException(err, "%s: %s (major=%u minor=%u)", context, message.c_str(),
        (unsigned int)major, (unsigned int)minor);
    return -1;
}

static int from_hex(unsigned char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

DLLLOCAL bool decode_hex(const char* str, std::vector<unsigned char>& out, ExceptionSink* xsink,
        const char* err, const char* context) {
    size_t len = strlen(str);
    if (len % 2) {
        xsink->raiseException(err, "%s: hex string must have even length", context);
        return false;
    }

    out.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2) {
        int hi = from_hex(str[i]);
        int lo = from_hex(str[i + 1]);
        if (hi < 0 || lo < 0) {
            xsink->raiseException(err, "%s: invalid hex character at position %d", context, (int)i);
            return false;
        }
        out.push_back((hi << 4) | lo);
    }
    return true;
}

DLLLOCAL bool decode_hex(const char* str, std::vector<unsigned char>& out, ExceptionSink* xsink,
        const char* context) {
    return decode_hex(str, out, xsink, "KRB5-TOKEN-ERROR", context);
}

DLLLOCAL QoreStringNode* encode_hex(const unsigned char* ptr, size_t len) {
    static const char* digits = "0123456789abcdef";
    QoreStringNode* str = new QoreStringNode;
    for (size_t i = 0; i < len; ++i) {
        str->concat(digits[(ptr[i] >> 4) & 0x0f]);
        str->concat(digits[ptr[i] & 0x0f]);
    }
    return str;
}

DLLLOCAL bool krb5_is_empty_cache_error(krb5_error_code rc) {
    return rc == KRB5_FCC_NOFILE || rc == KRB5_CC_NOTFOUND || rc == KRB5_CC_END;
}

static bool krb5_cache_backend_uses_filesystem(const char* type) {
    return !strcmp(type, "FILE") || !strcmp(type, "DIR");
}

static bool krb5_cache_backend_is_non_filesystem(const char* type) {
    return !strcmp(type, "MEMORY") || !strcmp(type, "API") || !strcmp(type, "KCM")
        || !strcmp(type, "KEYRING") || !strcmp(type, "MSLSA");
}

static bool krb5_check_cache_access(krb5_context ctx, krb5_ccache cache, int mode, ExceptionSink* xsink,
        const char* context) {
    QoreSandboxManagerHelper smh;
    if (!smh) {
        return true;
    }

    const char* type = krb5_cc_get_type(ctx, cache);
    const char* name = krb5_cc_get_name(ctx, cache);
    if (!type || !*type || !name || !*name) {
        xsink->raiseException("KRB5-CACHE-ERROR", "%s: credential cache metadata is unavailable", context);
        return false;
    }

    if (krb5_cache_backend_uses_filesystem(type)) {
        return smh->checkFilesystemAccess(name, mode, xsink);
    }

    if (krb5_cache_backend_is_non_filesystem(type)) {
        return true;
    }

    xsink->raiseException("KRB5-SANDBOX-ERROR",
        "%s: credential cache backend '%s' is not supported in sandboxed mode", context, type);
    return false;
}

static bool krb5_keytab_backend_uses_filesystem(const char* type) {
    return !strcmp(type, "FILE") || !strcmp(type, "WRFILE") || !strcmp(type, "DIR");
}

static bool krb5_keytab_backend_is_non_filesystem(const char* type) {
    return !strcmp(type, "MEMORY");
}

static const char* krb5_keytab_filesystem_path(const char* full_name) {
    const char* delim = strchr(full_name, ':');
    return delim ? delim + 1 : full_name;
}

static bool krb5_check_keytab_access(krb5_context ctx, krb5_keytab keytab, int mode, ExceptionSink* xsink,
        const char* context) {
    QoreSandboxManagerHelper smh;
    if (!smh) {
        return true;
    }

    const char* type = krb5_kt_get_type(ctx, keytab);
    if (!type || !*type) {
        xsink->raiseException("KRB5-KEYTAB-ERROR", "%s: keytab metadata is unavailable", context);
        return false;
    }

    char name[MAX_KEYTAB_NAME_LEN] = {0};
    krb5_error_code rc = krb5_kt_get_name(ctx, keytab, name, sizeof(name));
    if (rc) {
        krb5_raise_exception(xsink, ctx, rc, "KRB5-KEYTAB-ERROR", "getting keytab name for sandbox check");
        return false;
    }

    if (krb5_keytab_backend_uses_filesystem(type)) {
        return smh->checkFilesystemAccess(krb5_keytab_filesystem_path(name), mode, xsink);
    }

    if (krb5_keytab_backend_is_non_filesystem(type)) {
        return true;
    }

    xsink->raiseException("KRB5-SANDBOX-ERROR",
        "%s: keytab backend '%s' is not supported in sandboxed mode", context, type);
    return false;
}

DLLLOCAL QoreStringNode* krb5_unparse_principal(krb5_context ctx, krb5_const_principal principal, ExceptionSink* xsink,
        const char* err, const char* context) {
    char* name = nullptr;
    krb5_error_code rc = krb5_unparse_name(ctx, principal, &name);
    if (rc) {
        krb5_raise_exception(xsink, ctx, rc, err, context);
        return nullptr;
    }

    QoreStringNode* rv = new QoreStringNode(name);
    krb5_free_unparsed_name(ctx, name);
    return rv;
}

QoreKrb5Principal::QoreKrb5Principal(const char* p, ExceptionSink* xsink) {
    if (!p || !*p) {
        xsink->raiseException("KRB5-PRINCIPAL-ERROR", "principal string cannot be empty");
        return;
    }

    krb5_error_code rc = krb5_init_context(&ctx);
    if (rc) {
        krb5_raise_exception(xsink, nullptr, rc, "KRB5-INIT-ERROR", "initializing kerberos context");
        return;
    }

    rc = krb5_parse_name(ctx, p, &principal);
    if (rc) {
        krb5_raise_exception(xsink, ctx, rc, "KRB5-PRINCIPAL-ERROR", "parsing kerberos principal");
        return;
    }
}

QoreKrb5Principal::QoreKrb5Principal(krb5_context source_ctx, krb5_principal source_principal, ExceptionSink* xsink) {
    krb5_error_code rc = krb5_init_context(&ctx);
    if (rc) {
        krb5_raise_exception(xsink, nullptr, rc, "KRB5-INIT-ERROR", "initializing kerberos context");
        return;
    }

    rc = krb5_copy_principal(source_ctx, source_principal, &principal);
    if (rc) {
        krb5_raise_exception(xsink, source_ctx, rc, "KRB5-PRINCIPAL-ERROR", "copying kerberos principal");
    }
}

QoreKrb5Principal::QoreKrb5Principal(const QoreKrb5Principal& other, ExceptionSink* xsink) {
    krb5_error_code rc = krb5_init_context(&ctx);
    if (rc) {
        krb5_raise_exception(xsink, nullptr, rc, "KRB5-INIT-ERROR", "initializing kerberos context");
        return;
    }
    rc = krb5_copy_principal(ctx, other.principal, &principal);
    if (rc) {
        krb5_raise_exception(xsink, ctx, rc, "KRB5-PRINCIPAL-ERROR", "copying kerberos principal");
    }
}

QoreKrb5Principal::~QoreKrb5Principal() {
    if (principal) {
        krb5_free_principal(ctx, principal);
    }
    if (ctx) {
        krb5_free_context(ctx);
    }
}

QoreStringNode* QoreKrb5Principal::toString(ExceptionSink* xsink) const {
    return krb5_unparse_principal(ctx, principal, xsink, "KRB5-PRINCIPAL-ERROR",
        "unparsing kerberos principal");
}

QoreStringNode* QoreKrb5Principal::getRealm(ExceptionSink* xsink) const {
    const krb5_data* realm = krb5_princ_realm(ctx, principal);
    if (!realm || !realm->data) {
        xsink->raiseException("KRB5-REALM-ERROR", "kerberos principal does not have a realm");
        return nullptr;
    }
    return new QoreStringNode(realm->data, realm->length);
}

int QoreKrb5Principal::getComponentCount() const {
    return krb5_princ_size(ctx, principal);
}

QoreStringNode* QoreKrb5Principal::getComponent(int idx, ExceptionSink* xsink) const {
    if (idx < 0 || idx >= krb5_princ_size(ctx, principal)) {
        xsink->raiseException("KRB5-PRINCIPAL-ERROR", "principal component index %d out of range", idx);
        return nullptr;
    }
    const krb5_data* data = krb5_princ_component(ctx, principal, idx);
    return new QoreStringNode(data->data, data->length);
}

bool QoreKrb5Principal::equals(const QoreKrb5Principal& other) const {
    return krb5_principal_compare(ctx, principal, other.principal);
}

QoreGssClientContext::QoreGssClientContext(const char* service_principal, ExceptionSink* xsink) {
    if (!service_principal || !*service_principal) {
        xsink->raiseException("KRB5-GSS-ARG-ERROR", "service principal cannot be empty");
        return;
    }

    OM_uint32 min_stat = 0;
    gss_buffer_desc namebuf;
    namebuf.length = strlen(service_principal);
    namebuf.value = const_cast<char*>(service_principal);
    OM_uint32 maj = gss_import_name(&min_stat, &namebuf, GSS_C_NT_HOSTBASED_SERVICE, &target_name);
    if (maj != GSS_S_COMPLETE) {
        gss_raise_exception(xsink, "KRB5-GSS-ERROR", maj, min_stat, "importing GSSAPI target name");
        return;
    }

    target_display = service_principal;
}

QoreGssClientContext::~QoreGssClientContext() {
    reset();
    if (target_name != GSS_C_NO_NAME) {
        OM_uint32 min_stat = 0;
        gss_release_name(&min_stat, &target_name);
    }
}

QoreStringNode* QoreGssClientContext::getTargetName() const {
    return new QoreStringNode(target_display.c_str());
}

bool QoreGssClientContext::isComplete() const {
    return complete;
}

void QoreGssClientContext::reset() {
    if (ctx != GSS_C_NO_CONTEXT) {
        OM_uint32 min_stat = 0;
        gss_delete_sec_context(&min_stat, &ctx, GSS_C_NO_BUFFER);
        ctx = GSS_C_NO_CONTEXT;
    }
    complete = false;
}

QoreHashNode* QoreGssClientContext::step(const char* token_hex, ExceptionSink* xsink) {
    if (qore_check_cancel(xsink, "gssapi context initialization")) {
        return nullptr;
    }

    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    std::vector<unsigned char> input_bytes;
    if (token_hex && *token_hex) {
        if (!decode_hex(token_hex, input_bytes, xsink, "decoding GSSAPI input token")) {
            return nullptr;
        }
        input_token.value = input_bytes.data();
        input_token.length = input_bytes.size();
    }

    OM_uint32 actual_flags = 0;
    OM_uint32 lifetime = 0;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    OM_uint32 min_stat = 0;
    OM_uint32 maj = gss_init_sec_context(&min_stat, GSS_C_NO_CREDENTIAL, &ctx, target_name, mech,
        req_flags, 0, GSS_C_NO_CHANNEL_BINDINGS, input_token.length ? &input_token : GSS_C_NO_BUFFER, nullptr,
        &output_token, &actual_flags, &lifetime);

    if (maj != GSS_S_COMPLETE && maj != GSS_S_CONTINUE_NEEDED) {
        reset();
        gss_raise_exception(xsink, "KRB5-GSS-ERROR", maj, min_stat, "initializing GSSAPI security context");
        return nullptr;
    }

    complete = maj == GSS_S_COMPLETE;

    ReferenceHolder<QoreHashNode> rv(new QoreHashNode(autoTypeInfo), xsink);
    rv->setKeyValue("complete", complete, xsink);
    rv->setKeyValue("flags", (int64)actual_flags, xsink);
    rv->setKeyValue("lifetime", (int64)lifetime, xsink);
    if (output_token.length) {
        rv->setKeyValue("token", encode_hex(static_cast<const unsigned char*>(output_token.value), output_token.length), xsink);
    }
    gss_release_buffer(&min_stat, &output_token);
    return rv.release();
}

QoreKrb5CredentialCache::QoreKrb5CredentialCache(const char* cache_name, bool use_default, ExceptionSink* xsink) {
    krb5_error_code rc = krb5_init_context(&ctx);
    if (rc) {
        krb5_raise_exception(xsink, nullptr, rc, "KRB5-INIT-ERROR", "initializing kerberos context");
        return;
    }

    if (use_default) {
        rc = krb5_cc_default(ctx, &cache);
        if (rc) {
            krb5_raise_exception(xsink, ctx, rc, "KRB5-CACHE-ERROR", "opening default credential cache");
        }
        return;
    }

    if (!cache_name || !*cache_name) {
        xsink->raiseException("KRB5-CACHE-ERROR", "credential cache name cannot be empty");
        return;
    }

    rc = krb5_cc_resolve(ctx, cache_name, &cache);
    if (rc) {
        krb5_raise_exception(xsink, ctx, rc, "KRB5-CACHE-ERROR", "resolving credential cache");
    }
}

QoreKrb5CredentialCache::~QoreKrb5CredentialCache() {
    if (cache) {
        krb5_cc_close(ctx, cache);
    }
    if (ctx) {
        krb5_free_context(ctx);
    }
}

QoreStringNode* QoreKrb5CredentialCache::getName() const {
    return new QoreStringNode(krb5_cc_get_name(ctx, cache));
}

QoreStringNode* QoreKrb5CredentialCache::getType() const {
    return new QoreStringNode(krb5_cc_get_type(ctx, cache));
}

QoreStringNode* QoreKrb5CredentialCache::getFullName(ExceptionSink* xsink) const {
    char* full_name = nullptr;
    krb5_error_code rc = krb5_cc_get_full_name(ctx, cache, &full_name);
    if (rc) {
        krb5_raise_exception(xsink, ctx, rc, "KRB5-CACHE-ERROR", "getting credential cache full name");
        return nullptr;
    }

    QoreStringNode* rv = new QoreStringNode(full_name);
    krb5_free_string(ctx, full_name);
    return rv;
}

int QoreKrb5CredentialCache::initialize(const QoreKrb5Principal& principal, ExceptionSink* xsink) {
    if (!krb5_check_cache_access(ctx, cache, QSEC_WRITE | QSEC_CREATE, xsink, "initializing credential cache")) {
        return -1;
    }

    krb5_error_code rc = krb5_cc_initialize(ctx, cache, principal.principal);
    if (rc) {
        return krb5_raise_exception(xsink, ctx, rc, "KRB5-CACHE-ERROR", "initializing credential cache");
    }
    return 0;
}

bool QoreKrb5CredentialCache::hasPrimaryPrincipal(ExceptionSink* xsink) const {
    if (!krb5_check_cache_access(ctx, cache, QSEC_READ, xsink, "reading credential cache primary principal")) {
        return false;
    }

    krb5_principal principal = nullptr;
    krb5_error_code rc = krb5_cc_get_principal(ctx, cache, &principal);
    if (!rc) {
        krb5_free_principal(ctx, principal);
        return true;
    }
    if (krb5_is_empty_cache_error(rc)) {
        return false;
    }
    krb5_raise_exception(xsink, ctx, rc, "KRB5-CACHE-ERROR", "reading credential cache primary principal");
    return false;
}

QoreKrb5Principal* QoreKrb5CredentialCache::getPrimaryPrincipal(ExceptionSink* xsink) const {
    if (!krb5_check_cache_access(ctx, cache, QSEC_READ, xsink, "reading credential cache primary principal")) {
        return nullptr;
    }

    krb5_principal principal = nullptr;
    krb5_error_code rc = krb5_cc_get_principal(ctx, cache, &principal);
    if (rc) {
        krb5_raise_exception(xsink, ctx, rc, "KRB5-CACHE-ERROR", "reading credential cache primary principal");
        return nullptr;
    }

    SimpleRefHolder<QoreKrb5Principal> rv(new QoreKrb5Principal(ctx, principal, xsink));
    krb5_free_principal(ctx, principal);
    if (*xsink) {
        return nullptr;
    }
    return rv.release();
}

int QoreKrb5CredentialCache::storeCredentials(const QoreKrb5Credentials& c, ExceptionSink* xsink) {
    if (!krb5_check_cache_access(ctx, cache, QSEC_WRITE | QSEC_CREATE, xsink, "storing credentials")) {
        return -1;
    }

    krb5_error_code rc = krb5_cc_store_cred(ctx, cache, c.creds);
    if (rc) {
        return krb5_raise_exception(xsink, ctx, rc, "KRB5-CACHE-ERROR", "storing credentials");
    }
    return 0;
}

QoreListNode* QoreKrb5CredentialCache::listCredentials(ExceptionSink* xsink) const {
    if (!krb5_check_cache_access(ctx, cache, QSEC_READ, xsink, "listing credentials")) {
        return nullptr;
    }

    ReferenceHolder<QoreListNode> rv(new QoreListNode(hashdeclKrb5CredentialsInfo->getTypeInfo()), xsink);
    krb5_cc_cursor cursor;
    memset(&cursor, 0, sizeof(cursor));

    krb5_error_code rc = krb5_cc_start_seq_get(ctx, cache, &cursor);
    if (rc) {
        if (krb5_is_empty_cache_error(rc)) {
            return rv.release();
        }
        krb5_raise_exception(xsink, ctx, rc, "KRB5-CACHE-ERROR", "starting credential cache enumeration");
        return nullptr;
    }

    while (true) {
        krb5_creds creds;
        memset(&creds, 0, sizeof(creds));
        rc = krb5_cc_next_cred(ctx, cache, &cursor, &creds);
        if (krb5_is_empty_cache_error(rc)) {
            break;
        }
        if (rc) {
            krb5_cc_end_seq_get(ctx, cache, &cursor);
            krb5_raise_exception(xsink, ctx, rc, "KRB5-CACHE-ERROR", "enumerating credential cache");
            return nullptr;
        }

        SimpleRefHolder<QoreKrb5Credentials> c(new QoreKrb5Credentials(ctx, creds, xsink));
        krb5_free_cred_contents(ctx, &creds);
        if (*xsink) {
            krb5_cc_end_seq_get(ctx, cache, &cursor);
            return nullptr;
        }

        ReferenceHolder<QoreHashNode> info(c->getInfo(xsink), xsink);
        if (*xsink) {
            krb5_cc_end_seq_get(ctx, cache, &cursor);
            return nullptr;
        }

        rv->push(info.release(), xsink);
        if (*xsink) {
            krb5_cc_end_seq_get(ctx, cache, &cursor);
            return nullptr;
        }
    }

    krb5_cc_end_seq_get(ctx, cache, &cursor);
    return rv.release();
}

static int krb5_set_data_from_hex(krb5_data& data, const char* data_hex, ExceptionSink* xsink, const char* context) {
    std::vector<unsigned char> bytes;
    if (!decode_hex(data_hex, bytes, xsink, "KRB5-CREDENTIALS-ERROR", context)) {
        return -1;
    }
    if (bytes.empty()) {
        xsink->raiseException("KRB5-CREDENTIALS-ERROR", "%s: data cannot be empty", context);
        return -1;
    }

    data.data = static_cast<char*>(malloc(bytes.size()));
    if (!data.data) {
        xsink->raiseException("KRB5-CREDENTIALS-ERROR", "%s: memory allocation failed", context);
        return -1;
    }

    memcpy(data.data, bytes.data(), bytes.size());
    data.length = bytes.size();
    return 0;
}

QoreKrb5Credentials::QoreKrb5Credentials(const QoreKrb5Principal& client, const QoreKrb5Principal& server,
        const char* session_key_hex, krb5_enctype enctype, krb5_timestamp start_time, krb5_timestamp end_time,
        krb5_timestamp renew_until, krb5_flags flags, const char* ticket_hex, ExceptionSink* xsink) {
    krb5_error_code rc = krb5_init_context(&ctx);
    if (rc) {
        krb5_raise_exception(xsink, nullptr, rc, "KRB5-INIT-ERROR", "initializing kerberos context");
        return;
    }

    creds = static_cast<krb5_creds*>(calloc(1, sizeof(*creds)));
    if (!creds) {
        xsink->raiseException("KRB5-CREDENTIALS-ERROR", "memory allocation failed");
        return;
    }

    rc = krb5_copy_principal(ctx, client.principal, &creds->client);
    if (rc) {
        krb5_raise_exception(xsink, ctx, rc, "KRB5-CREDENTIALS-ERROR", "copying client principal");
        return;
    }

    rc = krb5_copy_principal(ctx, server.principal, &creds->server);
    if (rc) {
        krb5_raise_exception(xsink, ctx, rc, "KRB5-CREDENTIALS-ERROR", "copying server principal");
        return;
    }

    std::vector<unsigned char> key_data;
    if (!decode_hex(session_key_hex, key_data, xsink, "KRB5-CREDENTIALS-ERROR", "decoding session key")) {
        return;
    }
    if (key_data.empty()) {
        xsink->raiseException("KRB5-CREDENTIALS-ERROR", "session key cannot be empty");
        return;
    }

    krb5_keyblock* keyblock = nullptr;
    rc = krb5_init_keyblock(ctx, enctype, key_data.size(), &keyblock);
    if (rc) {
        krb5_raise_exception(xsink, ctx, rc, "KRB5-CREDENTIALS-ERROR", "allocating session keyblock");
        return;
    }

    memcpy(keyblock->contents, key_data.data(), key_data.size());
    creds->keyblock = *keyblock;
    keyblock->contents = nullptr;
    keyblock->length = 0;
    krb5_free_keyblock(ctx, keyblock);

    creds->times.starttime = start_time;
    creds->times.authtime = start_time;
    creds->times.endtime = end_time;
    creds->times.renew_till = renew_until;
    creds->ticket_flags = flags;

    if (krb5_set_data_from_hex(creds->ticket, ticket_hex, xsink, "decoding ticket data")) {
        return;
    }
}

QoreKrb5Credentials::QoreKrb5Credentials(krb5_context source_ctx, const krb5_creds& source_creds,
        ExceptionSink* xsink) {
    krb5_error_code rc = krb5_init_context(&ctx);
    if (rc) {
        krb5_raise_exception(xsink, nullptr, rc, "KRB5-INIT-ERROR", "initializing kerberos context");
        return;
    }

    rc = krb5_copy_creds(source_ctx, &source_creds, &creds);
    if (rc) {
        krb5_raise_exception(xsink, source_ctx, rc, "KRB5-CREDENTIALS-ERROR", "copying credentials");
    }
}

QoreKrb5Credentials::~QoreKrb5Credentials() {
    if (creds) {
        krb5_free_creds(ctx, creds);
    }
    if (ctx) {
        krb5_free_context(ctx);
    }
}

QoreHashNode* QoreKrb5Credentials::getInfo(ExceptionSink* xsink) const {
    ReferenceHolder<QoreHashNode> rv(new QoreHashNode(hashdeclKrb5CredentialsInfo, xsink), xsink);

    ReferenceHolder<QoreStringNode> client(
        krb5_unparse_principal(ctx, creds->client, xsink, "KRB5-CREDENTIALS-ERROR", "rendering client principal"), xsink);
    if (*xsink) {
        return nullptr;
    }

    ReferenceHolder<QoreStringNode> server(
        krb5_unparse_principal(ctx, creds->server, xsink, "KRB5-CREDENTIALS-ERROR", "rendering server principal"), xsink);
    if (*xsink) {
        return nullptr;
    }

    char enctype_name[128] = {0};
    if (krb5_enctype_to_name(creds->keyblock.enctype, false, enctype_name, sizeof(enctype_name))) {
        snprintf(enctype_name, sizeof(enctype_name), "etype-%d", (int)creds->keyblock.enctype);
    }

    rv->setKeyValue("client", client.release(), xsink);
    rv->setKeyValue("server", server.release(), xsink);
    rv->setKeyValue("enctype", (int64)creds->keyblock.enctype, xsink);
    rv->setKeyValue("enctype_name", new QoreStringNode(enctype_name), xsink);
    rv->setKeyValue("start_time", (int64)creds->times.starttime, xsink);
    rv->setKeyValue("end_time", (int64)creds->times.endtime, xsink);
    rv->setKeyValue("renew_until", (int64)creds->times.renew_till, xsink);
    rv->setKeyValue("ticket_flags", (int64)creds->ticket_flags, xsink);
    rv->setKeyValue("is_skey", (bool)creds->is_skey, xsink);
    rv->setKeyValue("ticket_size", (int64)creds->ticket.length, xsink);
    if (*xsink) {
        return nullptr;
    }

    return rv.release();
}

QoreKrb5Principal* QoreKrb5Credentials::getClientPrincipal(ExceptionSink* xsink) const {
    return new QoreKrb5Principal(ctx, creds->client, xsink);
}

QoreKrb5Principal* QoreKrb5Credentials::getServerPrincipal(ExceptionSink* xsink) const {
    return new QoreKrb5Principal(ctx, creds->server, xsink);
}

QoreKrb5Context::QoreKrb5Context(ExceptionSink* xsink) {
    krb5_error_code rc = krb5_init_context(&ctx);
    if (rc) {
        krb5_raise_exception(xsink, nullptr, rc, "KRB5-INIT-ERROR", "initializing kerberos context");
    }
}

QoreKrb5Context::~QoreKrb5Context() {
    if (ctx) {
        krb5_free_context(ctx);
    }
}

QoreStringNode* QoreKrb5Context::getDefaultRealm(ExceptionSink* xsink) const {
    char* realm = nullptr;
    krb5_error_code rc = krb5_get_default_realm(ctx, &realm);
    if (rc) {
        krb5_raise_exception(xsink, ctx, rc, "KRB5-REALM-ERROR", "getting default kerberos realm");
        return nullptr;
    }

    QoreStringNode* rv = new QoreStringNode(realm);
    krb5_free_default_realm(ctx, realm);
    return rv;
}

QoreStringNode* QoreKrb5Context::getDefaultCredentialCacheName(ExceptionSink* xsink) const {
    const char* name = krb5_cc_default_name(ctx);
    if (!name || !*name) {
        xsink->raiseException("KRB5-CACHE-ERROR", "the default credential cache name is not available");
        return nullptr;
    }

    return new QoreStringNode(name);
}

QoreStringNode* QoreKrb5Context::getDefaultKeytabName(ExceptionSink* xsink) const {
    char name[MAX_KEYTAB_NAME_LEN] = {0};
    krb5_error_code rc = krb5_kt_default_name(ctx, name, sizeof(name));
    if (rc) {
        krb5_raise_exception(xsink, ctx, rc, "KRB5-KEYTAB-ERROR", "getting default keytab name");
        return nullptr;
    }

    return new QoreStringNode(name);
}

QoreKrb5CredentialCache* QoreKrb5Context::openCredentialCache(const char* cache_name, ExceptionSink* xsink) const {
    return new QoreKrb5CredentialCache(cache_name, false, xsink);
}

QoreKrb5CredentialCache* QoreKrb5Context::openDefaultCredentialCache(ExceptionSink* xsink) const {
    return new QoreKrb5CredentialCache(nullptr, true, xsink);
}

QoreKrb5Keytab* QoreKrb5Context::openKeytab(const char* keytab_name, ExceptionSink* xsink) const {
    return new QoreKrb5Keytab(keytab_name, false, xsink);
}

QoreKrb5Keytab* QoreKrb5Context::openDefaultKeytab(ExceptionSink* xsink) const {
    return new QoreKrb5Keytab(nullptr, true, xsink);
}

QoreKrb5CredentialCache* QoreKrb5Context::createMemoryCredentialCache(const QoreKrb5Principal& principal,
        const char* cache_name, ExceptionSink* xsink) const {
    if (!cache_name || !*cache_name) {
        xsink->raiseException("KRB5-CACHE-ERROR", "memory credential cache name cannot be empty");
        return nullptr;
    }

    std::string full_name = "MEMORY:";
    full_name += cache_name;
    SimpleRefHolder<QoreKrb5CredentialCache> cache(new QoreKrb5CredentialCache(full_name.c_str(), false, xsink));
    if (*xsink) {
        return nullptr;
    }
    if (cache->initialize(principal, xsink)) {
        return nullptr;
    }
    return cache.release();
}

QoreKrb5Keytab::QoreKrb5Keytab(const char* keytab_name, bool use_default, ExceptionSink* xsink) {
    krb5_error_code rc = krb5_init_context(&ctx);
    if (rc) {
        krb5_raise_exception(xsink, nullptr, rc, "KRB5-INIT-ERROR", "initializing kerberos context");
        return;
    }

    if (use_default) {
        rc = krb5_kt_default(ctx, &keytab);
        if (rc) {
            krb5_raise_exception(xsink, ctx, rc, "KRB5-KEYTAB-ERROR", "opening default keytab");
        }
        return;
    }

    if (!keytab_name || !*keytab_name) {
        xsink->raiseException("KRB5-KEYTAB-ERROR", "keytab name cannot be empty");
        return;
    }

    rc = krb5_kt_resolve(ctx, keytab_name, &keytab);
    if (rc) {
        krb5_raise_exception(xsink, ctx, rc, "KRB5-KEYTAB-ERROR", "resolving keytab");
    }
}

QoreKrb5Keytab::~QoreKrb5Keytab() {
    if (keytab) {
        krb5_kt_close(ctx, keytab);
    }
    if (ctx) {
        krb5_free_context(ctx);
    }
}

QoreStringNode* QoreKrb5Keytab::getName(ExceptionSink* xsink) const {
    char name[MAX_KEYTAB_NAME_LEN] = {0};
    krb5_error_code rc = krb5_kt_get_name(ctx, keytab, name, sizeof(name));
    if (rc) {
        krb5_raise_exception(xsink, ctx, rc, "KRB5-KEYTAB-ERROR", "getting keytab name");
        return nullptr;
    }

    return new QoreStringNode(name);
}

QoreStringNode* QoreKrb5Keytab::getType() const {
    return new QoreStringNode(krb5_kt_get_type(ctx, keytab));
}

static QoreHashNode* krb5_keytab_entry_to_hash(krb5_context ctx, const krb5_keytab_entry& entry, ExceptionSink* xsink) {
    ReferenceHolder<QoreHashNode> rv(new QoreHashNode(hashdeclKrb5KeytabEntryInfo, xsink), xsink);

    ReferenceHolder<QoreStringNode> principal(
        krb5_unparse_principal(ctx, entry.principal, xsink, "KRB5-KEYTAB-ERROR", "rendering keytab principal"), xsink);
    if (*xsink) {
        return nullptr;
    }

    char enctype_name[128] = {0};
    if (krb5_enctype_to_name(entry.key.enctype, false, enctype_name, sizeof(enctype_name))) {
        snprintf(enctype_name, sizeof(enctype_name), "etype-%d", (int)entry.key.enctype);
    }

    rv->setKeyValue("principal", principal.release(), xsink);
    rv->setKeyValue("kvno", (int64)entry.vno, xsink);
    rv->setKeyValue("enctype", (int64)entry.key.enctype, xsink);
    rv->setKeyValue("enctype_name", new QoreStringNode(enctype_name), xsink);
    rv->setKeyValue("timestamp", (int64)entry.timestamp, xsink);
    rv->setKeyValue("key_size", (int64)entry.key.length, xsink);
    if (*xsink) {
        return nullptr;
    }

    return rv.release();
}

bool QoreKrb5Keytab::hasContent(ExceptionSink* xsink) const {
    if (!krb5_check_keytab_access(ctx, keytab, QSEC_READ, xsink, "checking keytab content")) {
        return false;
    }

    krb5_error_code rc = krb5_kt_have_content(ctx, keytab);
    if (!rc) {
        return true;
    }
    if (rc == KRB5_KT_NOTFOUND) {
        return false;
    }

    krb5_raise_exception(xsink, ctx, rc, "KRB5-KEYTAB-ERROR", "checking keytab content");
    return false;
}

int QoreKrb5Keytab::addEntry(const QoreKrb5Principal& principal, const char* key_hex, krb5_enctype enctype,
        krb5_kvno kvno, ExceptionSink* xsink) {
    if (!krb5_check_keytab_access(ctx, keytab, QSEC_WRITE | QSEC_CREATE, xsink, "adding keytab entry")) {
        return -1;
    }

    std::vector<unsigned char> key_data;
    if (!decode_hex(key_hex, key_data, xsink, "KRB5-KEYTAB-ERROR", "adding keytab entry")) {
        return -1;
    }
    if (key_data.empty()) {
        xsink->raiseException("KRB5-KEYTAB-ERROR", "adding keytab entry: key data cannot be empty");
        return -1;
    }

    krb5_keytab_entry entry;
    memset(&entry, 0, sizeof(entry));

    krb5_error_code rc = krb5_copy_principal(ctx, principal.principal, &entry.principal);
    if (rc) {
        return krb5_raise_exception(xsink, ctx, rc, "KRB5-KEYTAB-ERROR", "copying keytab principal");
    }

    krb5_keyblock* keyblock = nullptr;
    rc = krb5_init_keyblock(ctx, enctype, key_data.size(), &keyblock);
    if (rc) {
        krb5_free_principal(ctx, entry.principal);
        return krb5_raise_exception(xsink, ctx, rc, "KRB5-KEYTAB-ERROR", "allocating keytab keyblock");
    }

    memcpy(keyblock->contents, key_data.data(), key_data.size());
    entry.key = *keyblock;
    keyblock->contents = nullptr;
    keyblock->length = 0;
    krb5_free_keyblock(ctx, keyblock);

    entry.vno = kvno;
    entry.timestamp = time(nullptr);

    rc = krb5_kt_add_entry(ctx, keytab, &entry);
    krb5_free_keytab_entry_contents(ctx, &entry);
    if (rc) {
        return krb5_raise_exception(xsink, ctx, rc, "KRB5-KEYTAB-ERROR", "adding keytab entry");
    }

    return 0;
}

QoreHashNode* QoreKrb5Keytab::getEntry(const QoreKrb5Principal& principal, krb5_kvno kvno, krb5_enctype enctype,
        ExceptionSink* xsink) const {
    if (!krb5_check_keytab_access(ctx, keytab, QSEC_READ, xsink, "reading keytab entry")) {
        return nullptr;
    }

    krb5_keytab_entry entry;
    memset(&entry, 0, sizeof(entry));

    krb5_error_code rc = krb5_kt_get_entry(ctx, keytab, principal.principal, kvno, enctype, &entry);
    if (rc) {
        krb5_raise_exception(xsink, ctx, rc, "KRB5-KEYTAB-ERROR", "reading keytab entry");
        return nullptr;
    }

    ReferenceHolder<QoreHashNode> rv(krb5_keytab_entry_to_hash(ctx, entry, xsink), xsink);
    krb5_free_keytab_entry_contents(ctx, &entry);
    if (*xsink) {
        return nullptr;
    }

    return rv.release();
}

QoreListNode* QoreKrb5Keytab::listEntries(ExceptionSink* xsink) const {
    if (!krb5_check_keytab_access(ctx, keytab, QSEC_READ, xsink, "listing keytab entries")) {
        return nullptr;
    }

    ReferenceHolder<QoreListNode> rv(new QoreListNode(hashdeclKrb5KeytabEntryInfo->getTypeInfo()), xsink);
    krb5_kt_cursor cursor;
    memset(&cursor, 0, sizeof(cursor));

    krb5_error_code rc = krb5_kt_start_seq_get(ctx, keytab, &cursor);
    if (rc) {
        krb5_raise_exception(xsink, ctx, rc, "KRB5-KEYTAB-ERROR", "starting keytab enumeration");
        return nullptr;
    }

    while (true) {
        krb5_keytab_entry entry;
        memset(&entry, 0, sizeof(entry));
        rc = krb5_kt_next_entry(ctx, keytab, &entry, &cursor);
        if (rc == KRB5_KT_END) {
            break;
        }
        if (rc) {
            krb5_kt_end_seq_get(ctx, keytab, &cursor);
            krb5_raise_exception(xsink, ctx, rc, "KRB5-KEYTAB-ERROR", "enumerating keytab entries");
            return nullptr;
        }

        ReferenceHolder<QoreHashNode> info(krb5_keytab_entry_to_hash(ctx, entry, xsink), xsink);
        krb5_free_keytab_entry_contents(ctx, &entry);
        if (*xsink) {
            krb5_kt_end_seq_get(ctx, keytab, &cursor);
            return nullptr;
        }

        rv->push(info.release(), xsink);
        if (*xsink) {
            krb5_kt_end_seq_get(ctx, keytab, &cursor);
            return nullptr;
        }
    }

    krb5_kt_end_seq_get(ctx, keytab, &cursor);
    return rv.release();
}

static void krb5_module_init(QoreModuleInitContext& ctx, ExceptionSink& xsink) {
    krb5ns.addConstant("GSS_MUTUAL_FLAG", (int64)GSS_C_MUTUAL_FLAG);
    krb5ns.addConstant("GSS_SEQUENCE_FLAG", (int64)GSS_C_SEQUENCE_FLAG);
    krb5ns.addConstant("GSS_INTEG_FLAG", (int64)GSS_C_INTEG_FLAG);
    krb5ns.addConstant("GSS_CONF_FLAG", (int64)GSS_C_CONF_FLAG);
    krb5ns.addConstant("ENCTYPE_AES256_CTS_HMAC_SHA1_96", (int64)ENCTYPE_AES256_CTS_HMAC_SHA1_96);

    hashdeclKrb5KeytabEntryInfo = init_hashdecl_Krb5KeytabEntryInfo(krb5ns);
    hashdeclKrb5CredentialsInfo = init_hashdecl_Krb5CredentialsInfo(krb5ns);

    krb5ns.addSystemClass(initKrb5PrincipalClass(krb5ns));
    krb5ns.addSystemClass(initKrb5CredentialsClass(krb5ns));
    krb5ns.addSystemClass(initKrb5CredentialCacheClass(krb5ns));
    krb5ns.addSystemClass(initKrb5KeytabClass(krb5ns));
    krb5ns.addSystemClass(initKrb5ContextClass(krb5ns));
    krb5ns.addSystemClass(initGssClientContextClass(krb5ns));
}

static void krb5_module_ns_init(QoreNamespace* rns, QoreNamespace* qns, ExceptionSink& xsink) {
    qns->addNamespace(krb5ns.copy());
}

static void krb5_module_delete() {
    krb5ns.clear(nullptr);
}
