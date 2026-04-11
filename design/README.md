# module-krb5 Design Notes

This directory collects the higher-level design decisions behind the Qore
`krb5` module that would otherwise be invisible from the code itself.

## Per-object krb5 contexts

Every `QoreKrb5Principal`, `QoreKrb5Credentials`, `QoreKrb5CredentialCache`,
`QoreKrb5Keytab`, and `QoreKrb5Context` wrapper creates and owns its own
`krb5_context`. MIT Kerberos contexts are not thread-safe, so sharing one
across independent Qore objects would require external locking. Per-object
contexts also make the lifetime model trivial: the C++ destructor is the only
place each context is freed.

The cost is that APIs which conceptually take values "from" one context and
apply them to another (for example storing credentials produced in one object
into a cache owned by another) must copy through the destination's context.
See `QoreKrb5CredentialCache::storeCredentials()` in `src/krb5-module.cpp` for
an example: it calls `krb5_copy_creds()` into the cache's own context before
calling `krb5_cc_store_cred()`.

## Sandbox model

The module is intended to be used inside Qorus services where filesystem
access is tightly controlled. Rather than marking each class with the maximum
possible domain set, the binding uses two layers:

1. **Class/method domains** (`dom=FILESYSTEM`, `dom=NETWORK`) declared in the
   `.qpp` files enforce coarse-grained program-level access control through
   Qore parse options (for example `PO_NO_NETWORK`). `Krb5Context`,
   `Krb5CredentialCache`, `Krb5Keytab`, and `GssCredential` carry
   `dom=FILESYSTEM`; `GssClientContext` carries `dom=NETWORK`, and
   `Krb5Context::acquireCredentialsWith*` methods add `dom=NETWORK` because
   they contact the KDC. Pure data classes (`Krb5Principal`, `Krb5Credentials`)
   carry no domain.

2. **Runtime sandbox checks** via `QoreSandboxManagerHelper` apply per
   operation. For file-backed cache and keytab backends the module calls
   `checkFilesystemAccess()` before each read/write. Backends that never touch
   the filesystem (`MEMORY`, `API`, `KCM`, `KEYRING`, `MSLSA` for caches;
   `MEMORY` for keytabs) are allowed through. Any backend outside those two
   allowlists is rejected with `KRB5-SANDBOX-ERROR` so that new MIT krb5
   backends do not accidentally become sandbox-reachable without review.

## Hex-encoded tokens

GSSAPI produces opaque binary blobs (initiator tokens, wrapped messages, keys)
that Qore-level code has no easy binary-safe path to handle. The module
standardises on hex encoding for all such values. The cost is a ~2x size
overhead on every token; the benefit is that every token is a plain `string`
that can be passed through `hash`, `list`, JSON, YAML, or a relational
database without encoding concerns, and the encoded values are safe to log
for diagnostics without risk of terminal injection.

## Exception safety

All wrapper classes inherit from `AbstractPrivateData`, hold raw MIT krb5 /
GSSAPI handles as members, and use destructors to release them. Construction
errors populate `ExceptionSink` and leave the member handles in a state the
destructor can safely release (typically `nullptr`). Callers are expected to
check `*xsink` after construction; the `SimpleRefHolder<>` / `ReferenceHolder<>`
pattern ensures partially-constructed objects are deleted along the error
path.

The module provides a local `GssBufferHolder` RAII wrapper around
`gss_buffer_desc` so that `gss_init_sec_context`, `gss_wrap`, and `gss_unwrap`
output buffers are released even on early-return error paths.

## Scope boundaries for 1.0

- Both initiator-side (`GssClientContext`) and acceptor-side (`GssAcceptorContext`)
  GSSAPI contexts, including channel bindings and message protection.
- Initial credential acquisition from passwords and keytabs, credential
  renewal, and service-ticket acquisition from an existing TGT.
- Credential lifecycle helpers for expiry and renewal-threshold evaluation.
- Keytab management: adding, removing, enumerating, highest-kvno discovery,
  and old-entry cleanup.
- SPNEGO helpers for HTTP Negotiate token envelopes and client/server
  header-level token loops.
- Basic credential delegation through `GssAcceptorContext`.
- GSSAPI MIC (Message Integrity Code) compute and verify.
- Credential cache collection discovery across all configured backends.
- S4U2Self credential impersonation via `gss_acquire_cred_impersonate_name()`
  and S4U2Proxy constrained delegation via `KRB5_GC_CONSTRAINED_DELEGATION`.
- Credential renewal workflow helper (`renewAndStoreIfNeeded`).
- Kerberos environment validation helper (`validateKerberosEnvironment`).
- No KDC replication, admin (kadmin) operations, or prompter callbacks.

## Logging model

Higher-level helper APIs should use `Logger::LoggerInterface` as their
primary logging integration point. Low-level binary module APIs keep
exceptions as the behavioral contract and avoid logging directly unless a
future C++ binding has a clear Qore object lifetime model for logger handles.

Logs must never contain passwords, session keys, raw tickets, raw GSS tokens,
or delegated credential material. Safe diagnostics include operation names,
principal names, realms, cache/keytab backend types, enctypes, token sizes,
and ticket lifetimes.

## Planned extensions

- **HTTP Negotiate workflows** — web-server adapter examples, session binding
  patterns, and policy checks around completed contexts.
- **Credential lifecycle workflows** — logger-aware renew-and-store loop
  helpers with configurable retry and backoff for long-running services.
- **Keytab rotation workflows** — dry-run reports, policy checks, and
  logger-aware keytab cleanup orchestration for service deployments.
- **Cross-realm trust ergonomics** — helpers around canonicalization and
  explicit realm handling for multi-tenant deployments.
- **SASL/GSSAPI integration** — higher-level helpers for LDAP and other
  SASL/GSSAPI bind patterns using MIC for final authentication steps.
