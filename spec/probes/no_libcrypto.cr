# Linkage probe: proves that Beryl's hashes, HMAC and key derivation link no
# OpenSSL. It requires only `beryl/crypto`, uses each family once, and is
# built without the standard library's OpenSSL bindings:
#
#     crystal-alpha build --release -Dwithout_openssl spec/probes/no_libcrypto.cr -o no_libcrypto
#     otool -L no_libcrypto   # macOS; `ldd no_libcrypto` on Linux
#
# The output of `otool -L` must list neither libssl nor libcrypto.
require "../../src/beryl/crypto"

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

STDOUT.puts "SHA-256(abc)           #{digest.hexstring}"
STDOUT.puts "HMAC-SHA256 (RFC 4231) #{tag.hexstring} verified=#{tag_is_accepted}"
STDOUT.puts "HKDF-SHA256            #{derived_key.hexstring}"
STDOUT.puts "SHA-512(abc)           #{sha512_digest.hexstring}"
STDOUT.puts "MD5(abc)               #{md5_digest.hexstring}"
STDOUT.puts "SHA-1(abc)             #{sha1_digest.hexstring}"
STDOUT.puts "PBKDF2-SHA256 (RFC 7914) #{salted_password.hexstring}"

is_correct = digest.hexstring == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" &&
             tag.hexstring == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" &&
             tag_is_accepted &&
             derived_key.hexstring == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8" &&
             salted_password.hexstring.starts_with?("55ac046e56e3089fec1691c22544b605")
exit(is_correct ? 0 : 1)
