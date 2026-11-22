require "./support/requested_spec_tag"

# The spec runner consumes ARGV as soon as it is required, so the tags asked
# for on the command line are noted first.
RequestedSpecTag.remember(ARGV)

require "spec"
require "../src/beryl"
require "./support/*"

# Builds each hash under test, by the name the standards use for it.
HASH_FUNCTION_BY_STANDARD_NAME = {
  "MD5"         => -> { Beryl::Crypto::Compatibility::MD5.new.as(Beryl::Crypto::V1::BlockHashFunction) },
  "SHA-1"       => -> { Beryl::Crypto::Compatibility::SHA1.new.as(Beryl::Crypto::V1::BlockHashFunction) },
  "SHA-224"     => -> { Beryl::Crypto::V1::SHA224.new.as(Beryl::Crypto::V1::BlockHashFunction) },
  "SHA-256"     => -> { Beryl::Crypto::V1::SHA256.new.as(Beryl::Crypto::V1::BlockHashFunction) },
  "SHA-384"     => -> { Beryl::Crypto::V1::SHA384.new.as(Beryl::Crypto::V1::BlockHashFunction) },
  "SHA-512"     => -> { Beryl::Crypto::V1::SHA512.new.as(Beryl::Crypto::V1::BlockHashFunction) },
  "SHA-512/256" => -> { Beryl::Crypto::V1::SHA512_256.new.as(Beryl::Crypto::V1::BlockHashFunction) },
}

# The same hashes as compile-time names, for specs that build generic types
# such as `HMAC(D)` in a macro loop: {standard name, class}.
LIST_OF_HASH_FUNCTION_NAMES = [
  {"MD5", "Beryl::Crypto::Compatibility::MD5"},
  {"SHA-1", "Beryl::Crypto::Compatibility::SHA1"},
  {"SHA-224", "Beryl::Crypto::V1::SHA224"},
  {"SHA-256", "Beryl::Crypto::V1::SHA256"},
  {"SHA-384", "Beryl::Crypto::V1::SHA384"},
  {"SHA-512", "Beryl::Crypto::V1::SHA512"},
  {"SHA-512/256", "Beryl::Crypto::V1::SHA512_256"},
]

# PBKDF2 vectors at or over this many iterations (RFC 6070 case 4 and its
# Wycheproof copy, 16,777,216 iterations each) run under `--tag slow`, which
# is meant for a release build: `crystal-alpha spec --release --tag slow`.
SLOW_PBKDF2_ITERATION_COUNT = 1_000_000
