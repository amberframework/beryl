# Linkage probe: proves that Beryl's hashes, HMAC, key derivation, ciphers and
# certificate code link no OpenSSL. It requires only `beryl/crypto` and
# `beryl/certificates`, uses each family once, and is
# built without the standard library's OpenSSL bindings:
#
#     crystal-alpha build --release -Dwithout_openssl spec/probes/no_libcrypto.cr -o no_libcrypto
#     otool -L no_libcrypto   # macOS; `ldd no_libcrypto` on Linux
#
# The output of `otool -L` must list neither libssl nor libcrypto.
require "../../src/beryl/crypto"
require "../../src/beryl/certificates"

digest = Beryl::Crypto.digest("abc")
tag = Beryl::Crypto.authenticate("what do ya want for nothing?", key: "Jefe")
tag_is_accepted = Beryl::Crypto.verify_authentication("what do ya want for nothing?", tag, key: "Jefe")
derived_key = Beryl::Crypto.derive_key(("0b" * 22).hexbytes, bytesize: 42)
sha512_digest = Beryl::Crypto::V1::SHA512.digest("abc")
md5_digest = Beryl::Crypto::Compatibility::MD5.digest("abc")
sha1_digest = Beryl::Crypto::Compatibility::SHA1.digest("abc")
salted_password = Beryl::Crypto::Compatibility::PBKDF2(Beryl::Crypto::V1::SHA256).derive_key(
  "passwd", salt: "salt", iteration_count: 1, bytesize: 64
)

# RFC 8439 section 2.8.2, the XChaCha draft's Appendix A.3.1, and test case 4
# of the GCM specification.
cipher_key = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f".hexbytes
sunscreen = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
header = "50515253c0c1c2c3c4c5c6c7".hexbytes
chacha20_poly1305_sealed = Beryl::Crypto::V1::ChaCha20Poly1305.new(cipher_key).encrypt(
  sunscreen, nonce: "070000004041424344454647".hexbytes, associated_data: header
)
xchacha20_poly1305_sealed = Beryl::Crypto::V1::XChaCha20Poly1305.new(cipher_key).encrypt(
  sunscreen, nonce: "404142434445464748494a4b4c4d4e4f5051525354555657".hexbytes, associated_data: header
)
aes_gcm_sealed = Beryl::Crypto::V1::AESGCM.new("feffe9928665731c6d6a8f9467308308".hexbytes).encrypt(
  ("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" \
   "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39").hexbytes,
  nonce: "cafebabefacedbaddecaf888".hexbytes,
  associated_data: "feedfacedeadbeeffeedfacedeadbeefabaddad2".hexbytes,
)
aes_cbc = Beryl::Crypto::Compatibility::AESCBC.new(cipher_key)
aes_cbc_ciphertext = aes_cbc.encrypt(sunscreen, initialization_vector: cipher_key[0, 16])
aes_cbc_plaintext = aes_cbc.decrypt(aes_cbc_ciphertext, initialization_vector: cipher_key[0, 16])
encrypted_note = Beryl::Crypto.encrypt("a private note", key: cipher_key)
opened_note = Beryl::Crypto.decrypt(encrypted_note, key: cipher_key)

STDOUT.puts "SHA-256(abc)           #{digest.hexstring}"
STDOUT.puts "HMAC-SHA256 (RFC 4231) #{tag.hexstring} verified=#{tag_is_accepted}"
STDOUT.puts "HKDF-SHA256            #{derived_key.hexstring}"
STDOUT.puts "SHA-512(abc)           #{sha512_digest.hexstring}"
STDOUT.puts "MD5(abc)               #{md5_digest.hexstring}"
STDOUT.puts "SHA-1(abc)             #{sha1_digest.hexstring}"
STDOUT.puts "PBKDF2-SHA256 (RFC 7914) #{salted_password.hexstring}"
STDOUT.puts "ChaCha20-Poly1305 tag (RFC 8439)   #{chacha20_poly1305_sealed[-16, 16].hexstring}"
STDOUT.puts "XChaCha20-Poly1305 tag (draft)     #{xchacha20_poly1305_sealed[-16, 16].hexstring}"
STDOUT.puts "AES-128-GCM tag (GCM test case 4)  #{aes_gcm_sealed[-16, 16].hexstring}"
STDOUT.puts "AES-256-CBC round trip             #{aes_cbc_plaintext == sunscreen.to_slice}"
STDOUT.puts "Beryl::Crypto.encrypt round trip   #{opened_note == "a private note".to_slice}"

# Every Mozilla root read, and each one Beryl can use checked against its own
# self-signature.
list_of_roots = Beryl::Certificates::TrustStore.mozilla.list_of_certificates
self_signed_count = list_of_roots.count do |root|
  key = root.subject_public_key_info.verification_key
  key ? root.signed_by?(key) : false
end
STDOUT.puts "Mozilla roots, self-signatures    #{self_signed_count} of #{list_of_roots.size} verified"

is_correct = self_signed_count >= 100 &&
             digest.hexstring == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" &&
             tag.hexstring == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" &&
             tag_is_accepted &&
             derived_key.hexstring == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8" &&
             salted_password.hexstring.starts_with?("55ac046e56e3089fec1691c22544b605") &&
             chacha20_poly1305_sealed[-16, 16].hexstring == "1ae10b594f09e26a7e902ecbd0600691" &&
             xchacha20_poly1305_sealed[-16, 16].hexstring == "c0875924c1c7987947deafd8780acf49" &&
             aes_gcm_sealed[-16, 16].hexstring == "5bc94fbc3221a5db94fae95ae7121a47" &&
             aes_cbc_plaintext == sunscreen.to_slice &&
             opened_note == "a private note".to_slice
exit(is_correct ? 0 : 1)
