/* -*- mode: c++; indent-tabs-mode: nil -*- */
/*
    krb5-module.h

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

#ifndef _QORE_KRB5_MODULE_H
#define _QORE_KRB5_MODULE_H

#include <config.h>
#include <qore/Qore.h>
#include <qore/qore_thread.h>

#include <gssapi/gssapi.h>
#include <krb5.h>

#include <string>
#include <vector>

DLLLOCAL int krb5_raise_exception(ExceptionSink* xsink, krb5_context ctx, krb5_error_code rc,
    const char* err, const char* context);
DLLLOCAL int gss_raise_exception(ExceptionSink* xsink, const char* err, OM_uint32 major, OM_uint32 minor,
    const char* context);

DLLLOCAL QoreClass* initKrb5ContextClass(QoreNamespace& ns);
DLLLOCAL QoreClass* initKrb5CredentialCacheClass(QoreNamespace& ns);
DLLLOCAL QoreClass* initKrb5PrincipalClass(QoreNamespace& ns);
DLLLOCAL QoreClass* initGssClientContextClass(QoreNamespace& ns);

extern QoreClass* QC_KRB5CONTEXT;
extern qore_classid_t CID_KRB5CONTEXT;
extern QoreClass* QC_KRB5CREDENTIALCACHE;
extern qore_classid_t CID_KRB5CREDENTIALCACHE;
extern QoreClass* QC_KRB5PRINCIPAL;
extern qore_classid_t CID_KRB5PRINCIPAL;
extern QoreClass* QC_GSSCLIENTCONTEXT;
extern qore_classid_t CID_GSSCLIENTCONTEXT;

DLLLOCAL bool decode_hex(const char* str, std::vector<unsigned char>& out, ExceptionSink* xsink,
    const char* context);
DLLLOCAL QoreStringNode* encode_hex(const unsigned char* ptr, size_t len);
DLLLOCAL bool krb5_is_empty_cache_error(krb5_error_code rc);

class QoreKrb5Principal : public AbstractPrivateData {
public:
    krb5_context ctx = nullptr;
    krb5_principal principal = nullptr;

    DLLLOCAL explicit QoreKrb5Principal(const char* p, ExceptionSink* xsink);
    DLLLOCAL QoreKrb5Principal(krb5_context source_ctx, krb5_principal source_principal, ExceptionSink* xsink);
    DLLLOCAL QoreKrb5Principal(const QoreKrb5Principal& other, ExceptionSink* xsink);
    DLLLOCAL ~QoreKrb5Principal() override;

    DLLLOCAL QoreStringNode* toString(ExceptionSink* xsink) const;
    DLLLOCAL QoreStringNode* getRealm(ExceptionSink* xsink) const;
    DLLLOCAL int getComponentCount() const;
    DLLLOCAL QoreStringNode* getComponent(int idx, ExceptionSink* xsink) const;
    DLLLOCAL bool equals(const QoreKrb5Principal& other) const;
};

class QoreGssClientContext : public AbstractPrivateData {
public:
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_name_t target_name = GSS_C_NO_NAME;
    gss_OID mech = GSS_C_NO_OID;
    OM_uint32 req_flags = GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_INTEG_FLAG;
    bool complete = false;
    std::string target_display;

    DLLLOCAL explicit QoreGssClientContext(const char* service_principal, ExceptionSink* xsink);
    DLLLOCAL ~QoreGssClientContext() override;

    DLLLOCAL QoreStringNode* getTargetName() const;
    DLLLOCAL bool isComplete() const;
    DLLLOCAL void reset();
    DLLLOCAL QoreHashNode* step(const char* token_hex, ExceptionSink* xsink);
};

class QoreKrb5CredentialCache : public AbstractPrivateData {
public:
    krb5_context ctx = nullptr;
    krb5_ccache cache = nullptr;

    DLLLOCAL QoreKrb5CredentialCache(const char* cache_name, bool use_default, ExceptionSink* xsink);
    DLLLOCAL ~QoreKrb5CredentialCache() override;

    DLLLOCAL QoreStringNode* getName() const;
    DLLLOCAL QoreStringNode* getType() const;
    DLLLOCAL QoreStringNode* getFullName(ExceptionSink* xsink) const;
    DLLLOCAL int initialize(const QoreKrb5Principal& principal, ExceptionSink* xsink);
    DLLLOCAL bool hasPrimaryPrincipal(ExceptionSink* xsink) const;
    DLLLOCAL QoreKrb5Principal* getPrimaryPrincipal(ExceptionSink* xsink) const;
};

class QoreKrb5Context : public AbstractPrivateData {
public:
    krb5_context ctx = nullptr;

    DLLLOCAL explicit QoreKrb5Context(ExceptionSink* xsink);
    DLLLOCAL ~QoreKrb5Context() override;

    DLLLOCAL QoreStringNode* getDefaultRealm(ExceptionSink* xsink) const;
    DLLLOCAL QoreStringNode* getDefaultCredentialCacheName(ExceptionSink* xsink) const;
    DLLLOCAL QoreKrb5CredentialCache* openCredentialCache(const char* cache_name, ExceptionSink* xsink) const;
    DLLLOCAL QoreKrb5CredentialCache* openDefaultCredentialCache(ExceptionSink* xsink) const;
    DLLLOCAL QoreKrb5CredentialCache* createMemoryCredentialCache(const QoreKrb5Principal& principal,
        const char* cache_name, ExceptionSink* xsink) const;
};

#endif
