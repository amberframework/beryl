# Certificates

`Beryl::Certificates` reads X.509 certificates, certificate revocation lists and private key files, and verifies certificate chains for TLS (milestone B4). `Beryl::Encoding` holds the strict DER and PEM readers underneath. Both are written in Crystal: certificate signatures are checked with Beryl's own RSA, ECDSA and Ed25519, and nothing here links OpenSSL or PCRE2.

```crystal
require "beryl"

chain = Beryl::Certificates.read_pem_chain(File.read("chain.pem"))
path = Beryl::Certificates.verify_server_chain(chain, hostname: "example.com")
# => [leaf, intermediate, root], or raises Beryl::Certificates::VerificationFailed

key = Beryl::Certificates.read_private_key(File.read("server.key")) # PKCS #8, SEC 1 or PKCS #1

# Everything else is an argument of ChainVerification:
verification = Beryl::Certificates::ChainVerification.new(
  Beryl::Certificates::TrustStore.system, # or .mozilla (the default), or .from_pem(File.read("ca.pem"))
  limits: Beryl::Certificates::ChainVerification::Limits.new(largest_presented_certificate_count: 10),
)
verification.verify(leaf, intermediates,
  identity: Beryl::Certificates::ServiceIdentity.new("192.0.2.7"),
  purpose: Beryl::Certificates::Purpose::ClientAuthentication,
  time: Time.utc,
  list_of_revocation_lists: [crl])
```

`VerificationFailed#reason` is one of `FailureReason`: `MalformedLeaf`, `LeafExpiredOrNotYetValid`, `LeafProfileViolation`, `UsageNotAllowed`, `NameMismatch`, `NoTrustedPath`, `BudgetExceeded`, `Revoked` or `TooManyCertificates`; the message names the certificate and the rule.

## What is read

- **DER** (`Encoding::DistinguishedEncodingRules`, alias `DER`): X.690 §10 only. Definite, minimal lengths; minimal INTEGERs; BOOLEAN as 0x00 or 0xFF; BIT STRING unused bits zero; UTCTime and GeneralizedTime in their DER forms with `Z`; object identifiers minimally encoded. Nesting is limited to 32 levels and one input to 64 KiB (CRLs 16 MiB). Every malformed input raises `Encoding::MalformedEncoding` with its offset, or `Encoding::LimitExceeded`.
- **PEM** (`Encoding::PrivacyEnhancedMail`, alias `PEM`): RFC 7468 strict base64 between matching labels, 4 MiB per text.
- **Certificates**: versions 1 to 3 are read and chains accept version 3 only. Basic constraints, key usage, extended key usage, subject alternative names, name constraints, authority and subject key identifiers, certificate policies, policy constraints and authority information access are understood; any other critical extension fails verification. An explicitly encoded version 1, unique identifiers in a version 1 certificate, extensions below version 3, duplicate extensions, an empty extension list and an inner signature algorithm that differs from the outer one are refused when reading.
- **Keys**: RSA 2,048 to 8,192 bits, ECDSA on P-256 and P-384, Ed25519. Signatures: PKCS #1 v1.5 and PSS (MGF1 with the same hash, salt the hash length) with SHA-256, SHA-384 or SHA-512, ECDSA with SHA-256, SHA-384 or SHA-512, and Ed25519. P-521 keys and SHA-1 signatures are not accepted.
- **CRLs**: version 2, signed by the issuer with cRLSign, inside thisUpdate and nextUpdate, with a non-critical CRL number and no unknown critical extension.

## The profile a chain must meet

`ChainVerification` builds paths depth first, trust anchors before intermediates and candidates whose subject key identifier matches the child's authority key identifier first, backing out of any candidate that fails a check (so an extra expired or cross-signed intermediate does not hide the good path). It applies RFC 5280 §6 and the web PKI profile that rustls-webpki, Go and x509-limbo test; the full list is the documentation of `ChainVerification`. The choices that differ from a plain reading of RFC 5280:

- Name constraints follow RFC 5280 and the CA/Browser Forum: a wildcard name in a leaf is checked as the whole set of names it covers, so `*.example.com` falls inside an excluded `bad.example.com` (the case of CVE-2025-61727); directory names and the emailAddress attribute of the subject are checked as well as the SAN entries; constraints with a minimum or maximum, empty constraints and malformed bases are refused.
- A server leaf needs a subject alternative name, and only its SAN entries are matched against the host name (RFC 9525 §6.1). Common names must still be well formed (CA/Browser Forum §7.1.4.3): one written as an IP address must be canonical, a non-ASCII one is refused, and one that holds an A-label or equals a dNSName entry apart from letter case must be an exact copy of that entry. A common name absent from the SAN is accepted, as every other verifier on x509-limbo.com accepts it.
- Wildcards (RFC 9525): one `*` as the whole leftmost label, never over a public suffix (the Public Suffix List, pinned) or a single label.
- Serial numbers (positive, at most 20 bytes) are checked below the anchor only, and an anchor needs no subject key identifier: some Mozilla roots have a serial number of 0 (Starfield Services Root CA G2) or no subject key identifier (TWCA Global Root CA).
- A CA certificate may be a leaf when its cA bit and keyCertSign agree.
- A leaf or intermediate needs no authority key identifier (RFC 5280 §4.2.1.1 says a conforming CA includes one). Without it, Beryl finds the issuer by name and tries each certificate of that name by signature, as Go's crypto/x509 and OpenSSL do, so private CAs for PostgreSQL and MySQL that omit the extension verify. The limits below bound that search like any other.

## Trust stores

- `TrustStore.mozilla` (the default): the Mozilla root set with the Websites trust bit, from the CCADB report `IncludedRootsPEMTxt?TrustBitsInclude=Websites`, compiled into Beryl and pinned by sha256 (`MOZILLA_ROOTS_SHA256`, retrieved 2026-11-23, 112 roots). Verdicts are the same on every machine and change only with a Beryl release. 111 of the 112 roots are usable: e-Szigno TLS Root CA 2023 has a P-521 key. Mozilla's per-root "distrust for TLS after" dates are not applied.
- `TrustStore.system`: the first bundle found of `/etc/ssl/certs/ca-certificates.crt` (Debian, Ubuntu), `/etc/pki/tls/certs/ca-bundle.crt` (Fedora, RHEL), `/etc/ssl/ca-bundle.pem` (openSUSE) and `/etc/ssl/cert.pem` (Alpine, and macOS, where Apple ships and updates the system roots), or the file `SSL_CERT_FILE` names when that variable is set, as OpenSSL and Go read it. Certificates Beryl cannot read are skipped.
- `TrustStore.from_pem`: an application's own CA.

`scripts/update_certificate_data.rb PSL_COMMIT` refreshes the root set and the Public Suffix List and prints the new pins.

## Limits

`ChainVerification::Limits`, all constructor arguments:

| Limit | Default |
|---|---|
| Intermediates on one path | 8 |
| Signatures checked while building paths | 100 |
| Elapsed time for one verification | 50 ms |
| Certificates presented (leaf and intermediates) | 64 |
| Bytes presented | 64 KiB |
| Name constraint comparisons | 250,000 |

The presented-certificate default is 64 because x509-limbo's BetterTLS path-building cases present 36 certificates; a TLS client can pass a tighter limit.

## How it is tested

### x509-limbo: every applicable case

`spec/certificates/x509_limbo_spec.cr` runs every case of x509-limbo (pinned at commit b12423782a88abead01141fa6582254e3eb49e74, `limbo.json` sha256 `56799cefd65fc9e0bdb9cb0f97fce6734533b45df3de4fc17fdc7b7b79654fca`), which includes BetterTLS's path-building and name-constraint suites, the RFC 5280 and web PKI cases and the CVE regressions. `limbo.json` holds private keys that match the commit secret scan, so it stays out of git and `scripts/fetch_vectors.rb --missing` installs it, checked by sha256.

Of 9,807 cases, 9,793 run and every one matches its expected result (932 that must verify, 8,861 that must fail). Fourteen are skipped and the spec prints each: six need ML-DSA, and eight expect a result that a stronger source contradicts or that Beryl departs from to follow Go and OpenSSL:

| Case | Why Beryl differs |
|---|---|
| `webpki::eku::ee-without-eku` | conflicts with `rfc5280::eku::ee-without-eku`, which Beryl follows: a leaf without extended key usage is accepted (RFC 5280 §4.2.1.12), so private CAs for PostgreSQL and MySQL keep working. |
| `webpki::ca-as-leaf` | conflicts with `rfc5280::ca-as-leaf` and `pathlen::validation-ignores-pathlen-in-leaf`, which Beryl follows: a CA certificate may be the leaf when its cA bit and keyCertSign agree. |
| `rfc5280::nc::permitted-dns-match-noncritical` | conflicts with `webpki::nc::permitted-dns-match-noncritical`, which Beryl follows: non-critical name constraints are applied, as the baseline requirements allow. |
| `webpki::cn::not-in-san` | contradicted by 99 other cases (`rfc5280::nc::permitted-dns-match-more`, `webpki::san`, the BetterTLS suites) that expect a leaf whose common name is not among its dNSName entries to verify; every harness on x509-limbo.com accepts it. |
| `rfc5280::ski::root-missing-ski` | expects a root without a subject key identifier to fail; Mozilla's TWCA Global Root CA has none. |
| `rfc5280::aki::cross-signed-root-missing-aki` | marked pedantic, and contradicted by `cve::cve-2024-0567`, whose cross-signed trust anchor has no authority key identifier yet must verify. |
| `rfc5280::aki::leaf-missing-aki` | Beryl follows Go crypto/x509 and OpenSSL: a leaf without an authority key identifier is matched to its issuer by name and signature. Private CAs for PostgreSQL and MySQL often omit the extension. |
| `rfc5280::aki::intermediate-missing-aki` | the same, for an intermediate. |

### Wycheproof keys from DER

`spec/certificates/wycheproof_der_key_spec.cr` reads every Wycheproof public key from its DER SubjectPublicKeyInfo through `SubjectPublicKeyInfo`, the path a certificate's key takes, and checks every case: ECDSA P-256 (484 cases) and P-384 (504), Ed25519 (210), RSA PKCS #1 v1.5 in 16 files (4,137) and P-256 ECDH with the peer key from DER (612), 5,947 cases, 275 of them `acceptable` with Beryl's decision recorded.

### Differential against OpenSSL

`spec/differential/libcrypto_certificate_differential.cr` compares Beryl with libcrypto over a real-world corpus: 40,960 consecutive entries of Cloudflare's Nimbus2026 Certificate Transparency log from index 6,800,000,000, each with the chain its submitter logged (`scripts/fetch_certificate_corpus.rb`, sha256 `e3f14969b8a9ce9da45da21db9d01728c2e8435196f377b11fd6afe181555888`, 167 MB, kept out of git). OpenSSL accepts a certificate when `d2i_X509` consumes every byte and sets no `EXFLAG_INVALID`.

Results against OpenSSL 4.1.0 (23 Oct 2026) on m4-mini-01, 2026-11-23:

- **Reading**: all 20,698 distinct certificates of the corpus (leaves, precertificates and their issuers) are accepted by both. Beryl reads one in 2.5 µs (median), 8.5 µs at the 99.9th percentile.
- **Verifying**: all 40,960 logged chains get the same verdict, verified against the Mozilla roots at the log time with the host name checked (a DNS name of the leaf; the purpose alone when it has none). 10,365 verify in both (7,662 with a host name, 2,703 by purpose); the 30,595 precertificates are refused by both, for their critical CT poison extension. The slowest Beryl verification took 7.3 ms.
- **Mutants**: 1,000,000 certificates mutated Frankencert style (seed 20261123: a bit flipped, a byte set, inserted or deleted, a length or tag changed, a length pushed into its long form, an element spliced in from another certificate). No crash, and no reading over the 10 ms limit when repeated (a first reading over it, repeated in microseconds, is a collector pause, and the run reports each one). 962,270 verdicts agree (221,358 accepted by both, 740,912 refused by both). Every disagreement is explained below.

Where Beryl refuses a mutant that OpenSSL accepts (37,729), Beryl is applying a rule of DER or RFC 5280 that OpenSSL's `d2i_X509` leaves for later or does not apply:

| Class | Mutants | Why Beryl refuses |
|---|---|---|
| String contents | 20,521 | An IA5String outside ASCII, a PrintableString or NumericString outside its alphabet, or a name value of a type no name uses. OpenSSL stores string bytes without checking their alphabet; Go refuses the same strings. |
| Structure inside extension values | 5,274 | A wrong tag or constructed bit, a length past the end of its value, bytes after the last element, a malformed OBJECT IDENTIFIER or INTEGER, a GeneralName with an unknown or wrongly encoded tag, an empty list. OpenSSL decodes most extensions only when they are used (certificate policies, authority information access, extensions it does not know); Beryl reads every extension it understands when it reads the certificate and requires the others to be DER, as RFC 5280 §4.1 says extnValue is. |
| Signature algorithm differs | 5,248 | The algorithm inside the signed part differs from the one outside it (RFC 5280 §4.1.1.2). OpenSSL makes the same check, but when the signature is verified rather than when the certificate is read. |
| Time not in its DER form | 5,109 | A UTCTime or GeneralizedTime with a character that is not a digit, the wrong length, or a field out of range. OpenSSL checks validity times when it compares them. |
| BER forms DER forbids | 1,297 | A BOOLEAN other than 00 or FF, a tag or length in a longer form than needed, an indefinite length, a constructed string, nonzero unused bits in a BIT STRING (X.690 §10 and §11). |
| Explicit default version | 195 | Version 1 written out, which DER omits as the default. |
| Duplicate extension | 85 | RFC 5280 §4.2 allows each extension once; OpenSSL flags duplicates only among the extensions it caches. |

Where Beryl accepts a mutant that OpenSSL refuses (1): the mutation turned an extension into `sbgp-ipAddrBlock` (RFC 3779 IP address delegation) with contents that are not that structure. Beryl does not interpret RFC 3779 extensions; non-critical, they change nothing in Beryl's verdicts, and a critical one fails verification as an unknown critical extension.

Earlier runs of the same seed found 11,201 mutants of this second kind, and each class was closed in Beryl rather than explained away: name attribute values are now checked as their string types (valid UTF-8, the PrintableString alphabet, no surrogates in a BMPString, Unicode characters in a UniversalString, OpenSSL's set of value types), the parameters of key algorithms are checked as DER, CRL distribution points, freshest CRL and issuer alternative names are read, an EDIPartyName and an otherName are checked, and a key usage with no bit set is refused (RFC 5280 §4.2.1.3).

### Fuzzing the DER parser

`spec/fuzz/der_parser_fuzz.cr` mutates inputs the same way, one to four mutations stacked, starting from the 20,698 corpus certificates and the 30,391 other certificates, CRLs and keys of x509-limbo (51,089 seeds). It hands each mutant to every reader: the generic DER walk, `Certificate` (and its key and names), `CertificateRevocationList`, `SubjectPublicKeyInfo`, `PrivateKeyFile` and PEM, and one in sixteen to a full `ChainVerification` under its logged chain. A finding is an exception other than a `Beryl::Error`, a reader slower than 10 ms (60 ms for a verification) every time it is run, or the process dying.

The campaign on the final code ran 10,000,000 inputs (seeds 11 to 14, 2,500,000 each, about four minutes per seed on one core of an Apple M4) with **0 findings**; four seeds on the code before the last stricter-reading changes ran another 10,000,000 with 0 findings. Under four parallel runs about one input in 7,000 met a collector pause of 10 to 90 ms on its first reading and read again in microseconds; those are counted apart. CI runs 1,000,000 inputs on every pull request, seeded by the run number.

```sh
crystal-alpha build --release spec/fuzz/der_parser_fuzz.cr -o der_parser_fuzz
./der_parser_fuzz 2500000 11 spec/vectors/x509-limbo/limbo.json
```

## Speed

`bench/certificates_against_libcrypto.cr` against OpenSSL 4.0.1, on m4-mini-01 (Apple M4) with all ten cores reserved for the run: ten rounds of 2 s of processor time per arm, the arms taking turns of 5 ms and counting thread processor time. Inputs are the first 256 distinct certificates of the corpus and two logged chains verified against the Mozilla roots at their log time with the host name checked. Milestone F3b code (commit 05d1481).

| Operation | Beryl operations/s (median) | libcrypto operations/s (median) | Beryl against libcrypto (median of rounds) | Paired 95% interval | At least as fast |
|---|---|---|---|---|---|
| read 256 certificates, Beryl leaving keys until used | 1478 | 238 | 6.21× as fast | 6.2× as fast to 6.22× as fast | yes |
| read 256 certificates, public keys decoded | 1264 | 241 | 5.27× as fast | 5.25× as fast to 5.29× as fast | yes |
| verify a chain with an ECDSA leaf (two ECDSA signatures and one RSA signature) | 5461 | 4071 | 1.34× as fast | 1.34× as fast to 1.34× as fast | yes |
| verify a chain with an RSA leaf (three RSA signatures) | 27230 | 23201 | 1.17× as fast | 1.17× as fast to 1.17× as fast | yes |

Reading a certificate takes Beryl about 2.7 µs and OpenSSL about 16.6 µs. `d2i_X509` also builds every public key, and Beryl builds a key only when a signature is first checked with it; counting that work, Beryl is still 5.3 times as fast, because `RSA::PublicKey` now leaves its Montgomery constants (R² mod n) until its first operation. Before milestone F3b, building those constants with every key (about 128 µs per RSA key) made this row 4.06 times slower. Chain verification follows the signature speeds in [crypto/public-key.md](crypto/public-key.md): on main after F3, against the same OpenSSL in the same session, a chain with an ECDSA leaf was 1.34 times as fast and one with an RSA leaf 1.55 times slower; F3b brings the RSA chain to 1.17 times as fast.
