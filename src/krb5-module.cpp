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
#include "QC_Krb5Principal.h"

#include <cctype>

static QoreNamespace krb5ns("Qore::Krb5");

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
        const char* context) {
    size_t len = strlen(str);
    if (len % 2) {
        xsink->raiseException("KRB5-TOKEN-ERROR", "%s: token hex string must have even length", context);
        return false;
    }

    out.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2) {
        int hi = from_hex(str[i]);
        int lo = from_hex(str[i + 1]);
        if (hi < 0 || lo < 0) {
            xsink->raiseException("KRB5-TOKEN-ERROR", "%s: invalid hex character at position %d", context, (int)i);
            return false;
        }
        out.push_back((hi << 4) | lo);
    }
    return true;
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
    char* name = nullptr;
    krb5_error_code rc = krb5_unparse_name(ctx, principal, &name);
    if (rc) {
        krb5_raise_exception(xsink, ctx, rc, "KRB5-PRINCIPAL-ERROR", "unparsing kerberos principal");
        return nullptr;
    }
    QoreStringNode* str = new QoreStringNode(name);
    krb5_free_unparsed_name(ctx, name);
    return str;
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

static void krb5_module_init(QoreModuleInitContext& ctx, ExceptionSink& xsink) {
    krb5ns.addConstant("GSS_MUTUAL_FLAG", (int64)GSS_C_MUTUAL_FLAG);
    krb5ns.addConstant("GSS_SEQUENCE_FLAG", (int64)GSS_C_SEQUENCE_FLAG);
    krb5ns.addConstant("GSS_INTEG_FLAG", (int64)GSS_C_INTEG_FLAG);
    krb5ns.addConstant("GSS_CONF_FLAG", (int64)GSS_C_CONF_FLAG);

    krb5ns.addSystemClass(initKrb5PrincipalClass(krb5ns));
    krb5ns.addSystemClass(initGssClientContextClass(krb5ns));
}

static void krb5_module_ns_init(QoreNamespace* rns, QoreNamespace* qns, ExceptionSink& xsink) {
    qns->addNamespace(krb5ns.copy());
}

static void krb5_module_delete() {
    krb5ns.clear(nullptr);
}

