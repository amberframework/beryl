require "../spec_helper"
require "openssl"
require "openssl/hmac"
require "openssl/pkcs5"

# Differential test of Beryl against libcrypto: the same random input goes to
# both, and the outputs must be equal, byte for byte.
#
#     crystal-alpha spec --release --tag differential
#
# Every case draws its input from a generator seeded by the run seed, the
# algorithm and the case number, so one failing case replays alone:
#
#     BERYL_DIFFERENTIAL_SEED=<seed> BERYL_DIFFERENTIAL_FIRST_CASE=<case> \
#       BERYL_DIFFERENTIAL_CASE_COUNT=1 crystal-alpha spec --release --tag differential -e "<algorithm> equals"
#
# A debug build runs this file some twenty times slower; build with --release.
# One algorithm at a time is `-e "hash SHA-256 equals"`, `-e "HMAC-SHA-256 equals"`,
# `-e "HKDF-SHA-256 equals"` or `-e "PBKDF2-HMAC-SHA-256 matches"`.
#
# This file is the only place Beryl's repository touches OpenSSL besides the
# vector pin check; the library itself requires none of it.
lib LibCrypto
  # The version text of the libcrypto actually loaded (`OPENSSL_VERSION` = 0).
  fun beryl_spec_openssl_version = OpenSSL_version(kind : LibC::Int) : LibC::Char*
end

module LibcryptoDifferential
  # Hashes and HMACs run this many cases each unless told otherwise.
  DEFAULT_CASE_COUNT = 1_000_000

  # HKDF runs a tenth of the cases: each derives up to 255 blocks.
  HKDF_CASE_DIVISOR = 10

  # PBKDF2 runs a hundredth of the cases: each repeats HMAC up to 4,096 times.
  PBKDF2_CASE_DIVISOR = 100

  LARGEST_MESSAGE_BYTESIZE    = 65_536
  LARGEST_KEY_BYTESIZE        =    300
  LARGEST_UPDATE_COUNT        =      8
  LARGEST_PBKDF2_ITERATIONS   =  4_096
  LARGEST_PBKDF2_KEY_BYTESIZE =    160
  LARGEST_HKDF_INPUT_BYTESIZE =    300

  # Read once, at the edge of the spec run.
  record Settings, seed : UInt64, case_count : Int32, first_case : Int32 do
    def self.from_environment : Settings
      seed = ENV["BERYL_DIFFERENTIAL_SEED"]?.try(&.to_u64) || Random::Secure.rand(UInt64)
      case_count = ENV["BERYL_DIFFERENTIAL_CASE_COUNT"]?.try(&.to_i) || DEFAULT_CASE_COUNT
      first_case = ENV["BERYL_DIFFERENTIAL_FIRST_CASE"]?.try(&.to_i) || 0
      new(seed, case_count, first_case)
    end
  end

  class_getter settings : Settings { Settings.from_environment }

  # Returns the generator for one case. PCG32 takes a state and a stream; the
  # stream separates algorithms, the state separates cases.
  def self.generator_for(algorithm_number : Int32, case_number : Int32) : Random::PCG32
    Random::PCG32.new(settings.seed &+ case_number.to_u64 &* 0x9e3779b97f4a7c15_u64, algorithm_number.to_u64)
  end

  # Cuts *message* at random points and feeds the pieces to *digest* one
  # `update` at a time. One case in eight makes a single call.
  def self.update_in_random_pieces(digest : ::Digest, message : Bytes, generator : Random::PCG32) : Nil
    update_count = generator.rand(1..LARGEST_UPDATE_COUNT)
    offset = 0
    (update_count - 1).times do
      piece_bytesize = generator.rand(0..(message.size - offset))
      digest.update(message[offset, piece_bytesize])
      offset += piece_bytesize
    end
    digest.update(message[offset, message.size - offset])
  end

  def self.libcrypto_digest(libcrypto_name : String) : LibCrypto::EVP_MD
    evp_md = LibCrypto.evp_get_digestbyname(libcrypto_name)
    raise "libcrypto has no digest named #{libcrypto_name}" if evp_md.null?
    evp_md
  end

  # HMAC by libcrypto's one-shot `HMAC()`. A buffer that is never empty backs
  # the key so an empty key still passes a real pointer.
  def self.libcrypto_hmac(evp_md : LibCrypto::EVP_MD, key : Bytes, message : Bytes, tag : Bytes) : Bytes
    result = LibCrypto.hmac(evp_md, key.to_unsafe, key.size, message.to_unsafe, message.size, tag.to_unsafe, out tag_bytesize)
    raise "libcrypto HMAC failed" if result.null?
    tag[0, tag_bytesize]
  end

  # HKDF (RFC 5869) written directly on libcrypto's HMAC, as the reference.
  def self.reference_hkdf(evp_md : LibCrypto::EVP_MD, digest_bytesize : Int32, input_key_material : Bytes,
                          salt : Bytes, info : Bytes, bytesize : Int32) : Bytes
    zero_salt = Bytes.new(digest_bytesize)
    pseudorandom_key = libcrypto_hmac(evp_md, salt.empty? ? zero_salt : salt, input_key_material, Bytes.new(64)).dup
    derived_key = IO::Memory.new
    previous_block = Bytes.empty
    block_number = 0_u8
    while derived_key.size < bytesize
      block_number += 1
      block_input = IO::Memory.new
      block_input.write(previous_block)
      block_input.write(info)
      block_input.write_byte(block_number)
      previous_block = libcrypto_hmac(evp_md, pseudorandom_key, block_input.to_slice, Bytes.new(64)).dup
      derived_key.write(previous_block)
    end
    derived_key.to_slice[0, bytesize]
  end

  def self.describe_run(algorithm : String, case_count : Int32) : Nil
    STDOUT.puts "differential #{algorithm}: seed #{settings.seed}, cases #{settings.first_case}...#{settings.first_case + case_count}, " \
                "against #{String.new(LibCrypto.beryl_spec_openssl_version(0))}"
  end

  def self.report_mismatch(algorithm : String, case_number : Int32, detail : String, verb : String = "equals") : NoReturn
    fail "#{algorithm} differs from libcrypto at case #{case_number} with seed #{settings.seed}: #{detail}. " \
         "Replay: BERYL_DIFFERENTIAL_SEED=#{settings.seed} BERYL_DIFFERENTIAL_FIRST_CASE=#{case_number} " \
         "BERYL_DIFFERENTIAL_CASE_COUNT=1 crystal-alpha spec --release --tag differential -e \"#{algorithm} #{verb}\""
  end
end

if RequestedSpecTag.includes?("differential")
  describe "differential against libcrypto", tags: "differential" do
    {% for algorithm, algorithm_number in [{"MD5", "MD5", "Beryl::Crypto::Compatibility::MD5"},
                                           {"SHA-1", "SHA1", "Beryl::Crypto::Compatibility::SHA1"},
                                           {"SHA-224", "SHA224", "Beryl::Crypto::V1::SHA224"},
                                           {"SHA-256", "SHA256", "Beryl::Crypto::V1::SHA256"},
                                           {"SHA-384", "SHA384", "Beryl::Crypto::V1::SHA384"},
                                           {"SHA-512", "SHA512", "Beryl::Crypto::V1::SHA512"},
                                           {"SHA-512/256", "SHA512-256", "Beryl::Crypto::V1::SHA512_256"}] %}
      it "hash {{ algorithm[0].id }} equals libcrypto on random messages and update splits" do
        settings = LibcryptoDifferential.settings
        LibcryptoDifferential.describe_run("hash {{ algorithm[0].id }}", settings.case_count)
        beryl_hash = {{ algorithm[2].id }}.new
        libcrypto_hash = OpenSSL::Digest.new({{ algorithm[1] }})
        message_storage = Bytes.new(LibcryptoDifferential::LARGEST_MESSAGE_BYTESIZE)
        beryl_digest = Bytes.new({{ algorithm[2].id }}::DIGEST_SIZE)
        libcrypto_digest = Bytes.new({{ algorithm[2].id }}::DIGEST_SIZE)
        bytes_hashed = 0_u64

        settings.case_count.times do |case_offset|
          case_number = settings.first_case + case_offset
          generator = LibcryptoDifferential.generator_for({{ algorithm_number }}, case_number)
          message = message_storage[0, generator.rand(0..LibcryptoDifferential::LARGEST_MESSAGE_BYTESIZE)]
          generator.random_bytes(message)
          bytes_hashed += message.size

          beryl_hash.reset
          LibcryptoDifferential.update_in_random_pieces(beryl_hash, message, generator)
          beryl_hash.final(beryl_digest)
          libcrypto_hash.reset
          libcrypto_hash.update(message)
          libcrypto_hash.final(libcrypto_digest)

          unless beryl_digest == libcrypto_digest
            LibcryptoDifferential.report_mismatch(
              "hash {{ algorithm[0].id }}", case_number,
              "message of #{message.size} bytes, Beryl #{beryl_digest.hexstring}, libcrypto #{libcrypto_digest.hexstring}"
            )
          end
        end
        STDOUT.puts "differential hash {{ algorithm[0].id }}: #{settings.case_count} cases, #{bytes_hashed} bytes, 0 mismatches"
      end

      it "HMAC-{{ algorithm[0].id }} equals libcrypto on random keys, messages and update splits" do
        settings = LibcryptoDifferential.settings
        LibcryptoDifferential.describe_run("HMAC-{{ algorithm[0].id }}", settings.case_count)
        evp_md = LibcryptoDifferential.libcrypto_digest({{ algorithm[1] }})
        message_storage = Bytes.new(LibcryptoDifferential::LARGEST_MESSAGE_BYTESIZE)
        key_storage = Bytes.new(LibcryptoDifferential::LARGEST_KEY_BYTESIZE)
        beryl_tag = Bytes.new({{ algorithm[2].id }}::DIGEST_SIZE)
        libcrypto_tag_storage = Bytes.new(64)
        bytes_authenticated = 0_u64

        settings.case_count.times do |case_offset|
          case_number = settings.first_case + case_offset
          generator = LibcryptoDifferential.generator_for(100 + {{ algorithm_number }}, case_number)
          key = key_storage[0, generator.rand(0..LibcryptoDifferential::LARGEST_KEY_BYTESIZE)]
          generator.random_bytes(key)
          message = message_storage[0, generator.rand(0..LibcryptoDifferential::LARGEST_MESSAGE_BYTESIZE)]
          generator.random_bytes(message)
          bytes_authenticated += message.size

          authentication = Beryl::Crypto::V1::HMAC({{ algorithm[2].id }}).new(key)
          LibcryptoDifferential.update_in_random_pieces(authentication, message, generator)
          authentication.final(beryl_tag)
          libcrypto_tag = LibcryptoDifferential.libcrypto_hmac(evp_md, key, message, libcrypto_tag_storage)

          unless beryl_tag == libcrypto_tag
            LibcryptoDifferential.report_mismatch(
              "HMAC-{{ algorithm[0].id }}", case_number,
              "key of #{key.size} bytes, message of #{message.size} bytes, Beryl #{beryl_tag.hexstring}, libcrypto #{libcrypto_tag.hexstring}"
            )
          end

          # The same instance, reset, must verify the tag it just produced.
          authentication.reset
          authentication.update(message)
          unless authentication.verify(libcrypto_tag)
            LibcryptoDifferential.report_mismatch("HMAC-{{ algorithm[0].id }}", case_number, "verify refused libcrypto's tag")
          end
        end
        STDOUT.puts "differential HMAC-{{ algorithm[0].id }}: #{settings.case_count} cases, #{bytes_authenticated} bytes, 0 mismatches"
      end
    {% end %}

    {% for algorithm, algorithm_number in [{"SHA-1", "SHA1", "Beryl::Crypto::Compatibility::SHA1"},
                                           {"SHA-256", "SHA256", "Beryl::Crypto::V1::SHA256"},
                                           {"SHA-384", "SHA384", "Beryl::Crypto::V1::SHA384"},
                                           {"SHA-512", "SHA512", "Beryl::Crypto::V1::SHA512"}] %}
      it "HKDF-{{ algorithm[0].id }} equals a reference built on libcrypto's HMAC" do
        settings = LibcryptoDifferential.settings
        case_count = Math.max(settings.case_count // LibcryptoDifferential::HKDF_CASE_DIVISOR, 1)
        LibcryptoDifferential.describe_run("HKDF-{{ algorithm[0].id }}", case_count)
        evp_md = LibcryptoDifferential.libcrypto_digest({{ algorithm[1] }})
        digest_bytesize = {{ algorithm[2].id }}::DIGEST_SIZE

        case_count.times do |case_offset|
          case_number = settings.first_case + case_offset
          generator = LibcryptoDifferential.generator_for(200 + {{ algorithm_number }}, case_number)
          input_key_material = generator.random_bytes(generator.rand(0..LibcryptoDifferential::LARGEST_HKDF_INPUT_BYTESIZE))
          salt = generator.random_bytes(generator.rand(0..LibcryptoDifferential::LARGEST_HKDF_INPUT_BYTESIZE))
          info = generator.random_bytes(generator.rand(0..LibcryptoDifferential::LARGEST_HKDF_INPUT_BYTESIZE))
          bytesize = generator.rand(0..(255 * digest_bytesize))

          beryl_key = Beryl::Crypto::V1::HKDF({{ algorithm[2].id }}).derive_key(
            input_key_material, salt: salt, info: info, bytesize: bytesize
          )
          reference_key = LibcryptoDifferential.reference_hkdf(evp_md, digest_bytesize, input_key_material, salt, info, bytesize)

          unless beryl_key == reference_key
            LibcryptoDifferential.report_mismatch(
              "HKDF-{{ algorithm[0].id }}", case_number,
              "input of #{input_key_material.size} bytes, salt of #{salt.size}, info of #{info.size}, #{bytesize} bytes asked"
            )
          end
        end
        STDOUT.puts "differential HKDF-{{ algorithm[0].id }}: #{case_count} cases, 0 mismatches"
      end
    {% end %}

    {% for algorithm, algorithm_number in [{"SHA-1", "OpenSSL::Algorithm::SHA1", "Beryl::Crypto::Compatibility::SHA1"},
                                           {"SHA-256", "OpenSSL::Algorithm::SHA256", "Beryl::Crypto::V1::SHA256"},
                                           {"SHA-512", "OpenSSL::Algorithm::SHA512", "Beryl::Crypto::V1::SHA512"}] %}
      it "PBKDF2-HMAC-{{ algorithm[0].id }} matches OpenSSL::PKCS5.pbkdf2_hmac" do
        settings = LibcryptoDifferential.settings
        case_count = Math.max(settings.case_count // LibcryptoDifferential::PBKDF2_CASE_DIVISOR, 1)
        LibcryptoDifferential.describe_run("PBKDF2-HMAC-{{ algorithm[0].id }}", case_count)
        iterations_run = 0_u64

        case_count.times do |case_offset|
          case_number = settings.first_case + case_offset
          generator = LibcryptoDifferential.generator_for(300 + {{ algorithm_number }}, case_number)
          password = generator.random_bytes(generator.rand(0..LibcryptoDifferential::LARGEST_KEY_BYTESIZE))
          salt = generator.random_bytes(generator.rand(0..LibcryptoDifferential::LARGEST_KEY_BYTESIZE))
          iteration_count = generator.rand(1..LibcryptoDifferential::LARGEST_PBKDF2_ITERATIONS)
          bytesize = generator.rand(1..LibcryptoDifferential::LARGEST_PBKDF2_KEY_BYTESIZE)
          iterations_run += iteration_count

          beryl_key = Beryl::Crypto::Compatibility::PBKDF2({{ algorithm[2].id }}).derive_key(
            password, salt: salt, iteration_count: iteration_count, bytesize: bytesize
          )
          libcrypto_key = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iteration_count, {{ algorithm[1].id }}, bytesize)

          unless beryl_key == libcrypto_key
            LibcryptoDifferential.report_mismatch(
              "PBKDF2-HMAC-{{ algorithm[0].id }}", case_number,
              "password of #{password.size} bytes, salt of #{salt.size}, #{iteration_count} iterations, #{bytesize} bytes asked",
              verb: "matches"
            )
          end
        end
        STDOUT.puts "differential PBKDF2-HMAC-{{ algorithm[0].id }}: #{case_count} cases, #{iterations_run} iterations in total, 0 mismatches"
      end
    {% end %}
  end
end
