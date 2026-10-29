# Go transport consumers

`ProfileToSpec(profile.Spec)` validates and compiles a complete TLS profile into
a fresh uTLS preset without network I/O. It uses the same compiler as Session.
This entry is for consumers that own an already established raw connection,
including intercepting proxies; it avoids substituting the standard TLS stack
when a browser provider produces a complete Spec instead of a legacy fingerprint.

The caller owns the raw connection and must close it on failure, apply the
preset, use a cancellable handshake, and configure certificate verification.
HTTP/2 settings and header order are separate and are not applied by this helper.
The profile is cloned; neither the input nor another connection's preset is
mutated. Unsupported configurations fail before dialing when the caller invokes
the helper first. This API does not turn H1/H2 profiles into QUIC/H3 fingerprints.

CI uses a shared validation plan: ordinary development changes receive Linux
and Windows feedback on the current toolchain; main/v2 and explicit candidate
runs retain the original three platforms and both Go toolchains. Docs-only
changes omit Go execution. Missing, failed or cancelled planned jobs fail the
aggregate gate. Normal candidate tests cover core H3 and address-policy contracts
once; the existing manual workflows retain repeated and fuzz diagnostics.
