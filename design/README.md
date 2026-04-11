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
- Initial credential acquisition from passwords and keytabs.
- Keytab management: adding entries and enumerating.
- No KDC replication, admin (kadmin) operations, or prompter callbacks.

## Planned extensions

- **Credential delegation** — extracting delegated credentials from the
  acceptor context after an exchange with `GSS_C_DELEG_FLAG`.
- **Credential renewal** — `krb5_get_renewed_creds` for long-running services.
- **TGS service ticket requests** — `krb5_get_credentials` to obtain service
  tickets from a TGT without going through GSSAPI.
- **Keytab entry removal** — `krb5_kt_remove_entry` for key rotation workflows.
- **SPNEGO helpers** — RFC 4178 NegTokenInit / NegTokenResp envelope
  construction for HTTP Negotiate integration.
