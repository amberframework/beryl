# Public-key cryptography

`Beryl::Crypto` implements these standards in Crystal. Nothing here calls OpenSSL or any other C library.

Status: milestone B3 (make it work) of the Beryl cryptography plan, with the first portable speed work. Each section below lists the published vectors the code passes, its differential against OpenSSL, and its three constant-time checks. Those gates, not an outside audit, decide when Beryl becomes a default, and every pull request must pass them to merge.

## RSA

`Beryl::Crypto::V1::RivestShamirAdleman` (`RSA` for short) implements RFC 8017: PKCS #1 v1.5 signatures (§8.2), PSS signatures (§8.1) and OAEP encryption (§7.1). TLS and certificates need the signatures; MySQL's `caching_sha2_password` encrypts the password with OAEP over SHA-1.

```crystal
require "beryl"

alias RSA = Beryl::Crypto::V1::RSA
alias SHA256 = Beryl::Crypto::V1::SHA256

# A public key from its modulus (big-endian bytes) and public exponent.
public_key = RSA::PublicKey.new(modulus, 65_537)
public_key.verify_pkcs1_signature(message, signature, hash_function: SHA256)                # => true or false
public_key.verify_pss_signature(message, signature, hash_function: SHA256, salt_bytesize: 32) # => true or false
ciphertext = public_key.encrypt_with_oaep("password", hash_function: Beryl::Crypto::Compatibility::SHA1)

# A private key from the eight components of RFC 8017 §3.2.
private_key = RSA::PrivateKey.new(
  modulus: n, public_exponent: e, private_exponent: d,
  first_prime: p, second_prime: q,
  first_prime_exponent: d_p, second_prime_exponent: d_q, coefficient: q_inv,
)
private_key.sign_with_pkcs1(message, hash_function: SHA256)
private_key.sign_with_pss(message, hash_function: SHA256, salt_bytesize: 32)
private_key.decrypt_with_oaep(ciphertext, hash_function: Beryl::Crypto::Compatibility::SHA1) # => Bytes or nil
```

| Call | Hashes it takes | On bad input |
|---|---|---|
| `PrivateKey#sign_with_pkcs1` | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/256 | — |
| `PublicKey#verify_pkcs1_signature` | the same, and `Compatibility::SHA1` | `false` |
| `PrivateKey#sign_with_pss` | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/256, the same hash for MGF1 | `SaltTooLongForModulus` |
| `PublicKey#verify_pss_signature` | the same | `false` |
| `PublicKey#encrypt_with_oaep` | `Compatibility::SHA1` and the SHA-2 hashes above, the same hash for MGF1 | `MessageTooLongForModulus` |
| `PrivateKey#decrypt_with_oaep` | the same | `nil` |

A hash outside a scheme's list is a compile-time error. Verification never raises for a malformed signature, and decryption gives the same `nil` for every malformed ciphertext.

**Keys.** A public key takes a modulus of 2,048 to 8,192 bits; a private key, 2,048 to 4,096 bits with two primes. The public exponent is odd, from 3 to 2^32 - 1. Anything else raises `KeySizeNotSupported` or `PublicExponentNotSupported`. A private key is checked when it is built, in constant time and as one verdict: both primes odd and of about half the modulus size, their product the modulus, each exponent and the coefficient below its prime, the coefficient the inverse of q modulo p, d below the modulus; then one private operation is run and checked with the public exponent. A failure raises `MalformedPrivateKey`. Key generation and keys of three or more primes are not supported; keys come from key files, which Mica parses (milestone B4). `PrivateKey#wipe` (also run by the finalizer) overwrites the key's secret parts.

### How the code avoids leaking secrets

The arithmetic (`MontgomeryArithmetic`) follows BearSSL's `i31` and `i62` code on 64-bit words, with each word product a `UInt128`:

- Montgomery multiplication by finely integrated operand scanning (one pass per word adds both products), with one subtraction of the modulus at the end, kept or dropped by mask. A copy is compiled for 16, 24, 32, 48 and 64 words (the primes and moduli of 2,048, 3,072 and 4,096-bit keys), so the loops have a constant length.
- R² mod m without division: 1 doubled modulo m 65n times, then six Montgomery squarings. The low-word inverse by Newton's iteration.
- Exponentiation with a fixed window of 4 bits: the same squarings and one multiplication per window, the table entry chosen by reading every entry and keeping one by mask.
- The private operation by the Chinese remainder theorem, after BearSSL's `rsa_i31_priv.c`: the input is reduced into each prime's Montgomery form chunk by chunk (Horner's rule with R²), raised to d_p and d_q, and joined with Garner's formula. The result is raised to the public exponent and compared with the input before it is released; a mismatch (a fault in the computation) raises `FaultInPrivateKeyOperation`, as OpenSSL and BoringSSL check.
- OAEP decoding after BearSSL's `rsa_oaep_unpad.c`: every byte is read, every check folds into one verdict by mask, and the verdict (with the message length) passes once through `Declassification.reveal`. A ciphertext at or above the modulus folds into the same verdict.

Public-key operations (verification, encryption) work on public values only and may take time that depends on them.

Two kinds of value pass through `Declassification.reveal` besides verdicts: the size and low bit of a modulus and the value of the public exponent, which are public but read from a byte buffer; and the bit length of each prime, which sets the word count the arithmetic works in, as BearSSL also allows.

### How it is tested

(The counts below come from the runs recorded in the pull request.)

#### Published vectors

`crystal-alpha spec` prints the table after the suite.

| Scheme | CAVP | Wycheproof |
|---|---|---|
| PKCS #1 v1.5 verify | 216 | 4,137 |
| PKCS #1 v1.5 sign | 100 | 93 |
| PSS verify | 180 | 1,204 |
| PSS sign | 100 | — |
| OAEP decrypt | — | 417 |

Wycheproof cases marked `acceptable`, and how Beryl decides them:

- `rsa_signature_*` tcId 8, "Missing NULL in the ASN encoding": refused. Beryl compares the whole encoding with the one DigestInfo RFC 8017 §9.2 defines.
- `rsa_pkcs1_2048_sig_gen_test.json` SHA-1 group (tcId 65 to 72): Beryl signs with SHA-2 only; the published signatures verify.
- `rsa_pkcs1_{2048,3072}_sig_gen_test.json` "SmallPublicKey" groups (tcId 154, 155, 158, 156, 157): the key's primes differ in size by about a third of the modulus; `PrivateKey` refuses such a key, and the published signatures verify.
- `rsa_oaep_misc_test.json` tcId 376, 385, 392, "em represents a small integer": accepted.

The 1,024 and 1,536-bit sections and the three-prime OAEP files are below the key policy or outside two-prime keys. The files and parts left out, and why:

| Source | Left out | Why |
|---|---|---|
| CAVP `SigVer15_186-3.rsp`, `SigVerPSS_186-3.rsp`, and their `_TruncatedSHAs` files | the 1,024-bit sections | below the 2,048-bit minimum |
| CAVP `*_TruncatedSHAs` files | SHA-512/224 cases | SHA-512/224 is not implemented |
| CAVP `SigVerPSS_186-3.rsp` | SHA-1 cases | PSS takes SHA-2 only |
| CAVP `SigGen931*`, `SigVer931*`, `KeyGen*` | all | ANSI X9.31 signatures and key generation are not implemented |
| Wycheproof `rsa_signature_*_sha3_*`, `rsa_signature_2048_sha512_224_test.json` | all | SHA-3 and SHA-512/224 are not implemented |
| Wycheproof `rsa_pkcs1_{1024,1536}_sig_gen_test.json` | all | below the 2,048-bit minimum |
| Wycheproof `rsa_pkcs1_{2048,3072,4096}_test.json` | all | PKCS #1 v1.5 encryption is not implemented |
| Wycheproof `rsa_pss_*_shake*`, `rsa_pss_2048_sha512_224_mgf1_28_test.json` | all | SHAKE and SHA-512/224 are not implemented |
| Wycheproof `rsa_pss_2048_sha1_mgf1_20_test.json` | all | PSS takes SHA-2 only |
| Wycheproof `rsa_pss_2048_sha256_mgf1sha1_20_test.json` | all | MGF1 with a different hash than the message |
| Wycheproof `rsa_pss_*_params_test.json` | all | the key is given as DER with PSS parameters, which Mica parses (B4) |
| Wycheproof `rsa_pss_misc_test.json` | 126 of 150 cases | SHA-1, or MGF1 with a different hash |
| Wycheproof `rsa_oaep_*_mgf1sha1_test.json` where the message hash is not SHA-1 | all | MGF1 with a different hash than the message |
| Wycheproof `rsa_oaep_2048_sha512_224_*` | all | SHA-512/224 is not implemented |
| Wycheproof `rsa_oaep_misc_test.json` | 333 of 395 cases | MGF1 with a different hash, or a modulus outside 2,048 to 4,096 bits |
| Wycheproof `rsa_three_primes_oaep_*` | all | keys of three primes are not supported |

The Wycheproof files that carry private keys (`rsa_oaep_*`, `rsa_pkcs1_*_sig_gen_test.json`) match the commit secret scan, so they are kept out of git: `.gitignore` lists them, `spec/vectors/manifest.json` pins each by sha256, and `/usr/bin/ruby scripts/fetch_vectors.rb --missing` installs them (CI runs it before the specs).

#### Differential against OpenSSL

`spec/differential/libcrypto_rsa_differential_spec.cr`: libcrypto makes a pool of keys, Beryl builds the same keys from their components, and every case draws a hash, a message and a salt size or a label from the seeded generator. PKCS #1 v1.5 signatures must be equal byte for byte; PSS signatures and OAEP ciphertexts must be accepted by the other side; and a mutated signature, message, ciphertext or label (one bit flipped, or a value at or above the modulus) must get the same verdict from both. 20,000, 5,000 and 2,000 cases per scheme at 2,048, 3,072 and 4,096 bits, one process each. CI runs it on x86-64 and AArch64 Linux against the system OpenSSL 3.

#### Constant time, three methods

- Timing (`spec/constant_time/rsa_timing_spec.cr`, dudect's method): the private operation on a fixed input against random inputs, OAEP decoding of well-formed encodings against encodings broken at any place, and of encodings broken at the first byte against ones broken before the separator; |t| < 4.5. A planted early exit in OAEP decoding is reported. 200,000 measurements per class on the build Mac for each pull request, 50,000 in CI.
- Memory checker (`spec/probes/secret_taint.cr`, Linux CI): the Chinese remainder exponentiation with primes, exponents, coefficient, modulus and input all undefined to Memcheck at 2,048, 3,072 and 4,096 bits, the component check, and OAEP decoding under SHA-1 and SHA-256.
- Compiled code (`spec/probes/secret_flow.cr`, `scripts/check_secret_flow.rb`): key construction, PKCS #1 v1.5 and PSS signing, and OAEP decryption. `MontgomeryArithmetic` is a secret-buffer module and the RSA key types are cipher objects to the checker. A planted table lookup indexed by an exponent byte (`leaky_table_selection`) is reported.

### Speed

`bench/rsa_against_libcrypto.cr` measures operations per second for PKCS #1 v1.5 and PSS signing and verification and OAEP encryption and decryption at 2,048, 3,072 and 4,096 bits, against OpenSSL 4.1.0, in the same way as the cipher bench. The table for this page comes from the build Mac named in the pull request.
