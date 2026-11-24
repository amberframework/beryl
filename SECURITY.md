# Security policy

Beryl is cryptography and certificate verification for Amber apps. A way to
learn a secret from Beryl (from its timing, its memory accesses, its error
messages or its output), to forge or alter something Beryl accepts, to get a
certificate chain verified that should fail, or to crash or stall one of its
readers is a security bug, and we want to hear about it.

## Reporting a vulnerability

Report it privately through
[GitHub's private vulnerability reporting](https://github.com/amberframework/beryl/security/advisories/new)
(the **Report a vulnerability** button on the Security tab), or email
agent_c@agentc.consulting with "Beryl security" in the subject.

Please include the Beryl commit, the processor and operating system (the
code path differs on Apple Silicon, Linux AArch64, x86-64 and with the
`-Dberyl_portable_*` flags), and the smallest input or program that shows the
problem. A failing spec, a mismatch from one of the differentials, or a timing
run with its |t| value is ideal.

We confirm each report, keep you posted while we fix it, fix it in private,
and publish an advisory after the fix is released. We credit you in the
advisory unless you would rather stay anonymous.

## Supported versions

Beryl has no release yet. Security fixes land on `main`.

## What Beryl checks on every pull request

- Published vectors (NIST CAVP, the RFCs), Wycheproof and x509-limbo.
- A differential against OpenSSL on random and altered inputs for the ciphers,
  curves, RSA and certificates (the hashes and MACs on request).
- Constant time three ways: timing statistics after dudect, a Valgrind
  run with every secret marked undefined, and a taint check of the
  compiled LLVM IR.
- A DER fuzzer over every certificate reader.
- A probe that fails if the library links libssl or libcrypto.

Each guide in [docs/](docs/) lists its gates and how to run them.
