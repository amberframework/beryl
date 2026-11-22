# Speed of Beryl's authenticated ciphers next to libcrypto's.
#
#     crystal-alpha build --release bench/ciphers_against_libcrypto.cr -o ciphers_against_libcrypto
#     ./ciphers_against_libcrypto
#
# Method (plans/BERYL_TLS_CRYPTO.md section 3.1): both arms live in one
# binary and encrypt the same message under the same key, nonce and 13 bytes
# of associated data (the size of a TLS record header) into a reused
# buffer. Each arm keeps its keyed cipher between messages, as a connection
# does. They alternate, Beryl then libcrypto, for ten rounds; each arm of
# each round runs for at least two seconds. The figure reported is the
# median over the rounds of Beryl's MB/s divided by libcrypto's MB/s in the
# same round.
#
# BERYL_BENCH_SECONDS_PER_ARM and BERYL_BENCH_ROUNDS shorten a trial run.
require "openssl"
require "../src/beryl"

lib LibCrypto
  # The version text of the libcrypto actually loaded (`OPENSSL_VERSION` = 0).
  fun beryl_cipher_bench_openssl_version = OpenSSL_version(kind : LibC::Int) : LibC::Char*
  fun beryl_cipher_bench_evp_cipher_ctx_ctrl = EVP_CIPHER_CTX_ctrl(ctx : EVP_CIPHER_CTX, type : LibC::Int, arg : LibC::Int, ptr : Void*) : LibC::Int
end

module CiphersAgainstLibcrypto
  LIST_OF_MESSAGE_BYTESIZES = [64, 1024, 16 * 1024, 1024 * 1024]
  BYTES_PER_MEGABYTE        = 1_000_000.0
  TAG_BYTESIZE              =          16
  EVP_CTRL_AEAD_SET_IVLEN   =         0x9
  EVP_CTRL_AEAD_GET_TAG     =        0x10

  record Settings, seconds_per_arm : Float64, round_count : Int32 do
    def self.from_environment : Settings
      new(
        ENV["BERYL_BENCH_SECONDS_PER_ARM"]?.try(&.to_f) || 2.0,
        ENV["BERYL_BENCH_ROUNDS"]?.try(&.to_i) || 10,
      )
    end
  end

  # libcrypto's cipher, keyed once and reused for every message.
  class LibcryptoCipher
    def initialize(libcrypto_name : String, key : Bytes)
      cipher = LibCrypto.evp_get_cipherbyname(libcrypto_name)
      raise "libcrypto has no cipher named #{libcrypto_name}" if cipher.null?
      @context = LibCrypto.evp_cipher_ctx_new
      check LibCrypto.evp_cipherinit_ex(@context, cipher, Pointer(Void).null, Pointer(UInt8).null, Pointer(UInt8).null, 1)
      check LibCrypto.beryl_cipher_bench_evp_cipher_ctx_ctrl(@context, EVP_CTRL_AEAD_SET_IVLEN, 12, Pointer(Void).null)
      check LibCrypto.evp_cipherinit_ex(@context, Pointer(Void).null.as(LibCrypto::EVP_CIPHER), Pointer(Void).null, key, Pointer(UInt8).null, 1)
    end

    def encrypt(message : Bytes, sealed : Bytes, nonce : Bytes, associated_data : Bytes) : Nil
      written = 0
      check LibCrypto.evp_cipherinit_ex(@context, Pointer(Void).null.as(LibCrypto::EVP_CIPHER), Pointer(Void).null, Pointer(UInt8).null, nonce, 1)
      check LibCrypto.evp_cipherupdate(@context, Pointer(UInt8).null, pointerof(written), associated_data, associated_data.size)
      check LibCrypto.evp_cipherupdate(@context, sealed, pointerof(written), message, message.size)
      check LibCrypto.evp_cipherfinal_ex(@context, sealed.to_unsafe + written, pointerof(written))
      check LibCrypto.beryl_cipher_bench_evp_cipher_ctx_ctrl(@context, EVP_CTRL_AEAD_GET_TAG, TAG_BYTESIZE, (sealed.to_unsafe + message.size).as(Void*))
    end

    private def check(result : LibC::Int) : Nil
      raise "a libcrypto cipher call failed" unless result == 1
    end
  end

  # Runs the block over and over for at least *seconds* and returns MB/s.
  def self.megabytes_per_second(message_bytesize : Int32, seconds : Float64, & : -> Nil) : Float64
    # Check the clock every so many messages that the checks cost nothing.
    messages_per_clock_check = Math.max(1, 65_536 // message_bytesize)
    bytes_encrypted = 0_u64
    started_at = Time.instant
    elapsed_seconds = 0.0
    while elapsed_seconds < seconds
      messages_per_clock_check.times { yield }
      bytes_encrypted += messages_per_clock_check.to_u64 * message_bytesize
      elapsed_seconds = (Time.instant - started_at).total_seconds
    end
    bytes_encrypted / BYTES_PER_MEGABYTE / elapsed_seconds
  end

  def self.median(list_of_values : Array(Float64)) : Float64
    sorted = list_of_values.sort
    middle = sorted.size // 2
    sorted.size.odd? ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2
  end

  # States a ratio of Beryl's speed to libcrypto's the way Seth reads it.
  def self.describe_ratio(ratio : Float64) : String
    ratio >= 1.0 ? "#{ratio.round(2)}× as fast" : "#{(1.0 / ratio).round(2)}× slower"
  end

  def self.format_bytesize(bytesize : Int32) : String
    return "#{bytesize // (1024 * 1024)} MiB" if bytesize >= 1024 * 1024
    return "#{bytesize // 1024} KiB" if bytesize >= 1024

    "#{bytesize} B"
  end

  def self.run(io : IO) : Nil
    settings = Settings.from_environment
    io.puts "Beryl #{Beryl::VERSION} against #{String.new(LibCrypto.beryl_cipher_bench_openssl_version(0))}"
    io.puts "#{settings.round_count} rounds, Beryl then libcrypto in each, #{settings.seconds_per_arm} s per arm"
    io.puts
    io.puts "| Cipher | Message | Beryl MB/s (median) | libcrypto MB/s (median) | Beryl against libcrypto (median of rounds) | Range over rounds |"
    io.puts "|---|---|---|---|---|---|"

    {% for cipher in [{"ChaCha20-Poly1305", "chacha20-poly1305", 32, "Beryl::Crypto::V1::ChaCha20Poly1305"},
                      {"AES-128-GCM", "aes-128-gcm", 16, "Beryl::Crypto::V1::AESGCM"},
                      {"AES-256-GCM", "aes-256-gcm", 32, "Beryl::Crypto::V1::AESGCM"}] %}
      LIST_OF_MESSAGE_BYTESIZES.each do |message_bytesize|
        key = Random::Secure.random_bytes({{ cipher[2] }})
        nonce = Random::Secure.random_bytes(12)
        associated_data = Random::Secure.random_bytes(13)
        message = Random::Secure.random_bytes(message_bytesize)
        beryl_cipher = {{ cipher[3].id }}.new(key)
        libcrypto_cipher = LibcryptoCipher.new({{ cipher[1] }}, key)
        beryl_sealed = Bytes.new(message_bytesize + TAG_BYTESIZE)
        libcrypto_sealed = Bytes.new(message_bytesize + TAG_BYTESIZE)

        list_of_beryl_speeds = [] of Float64
        list_of_libcrypto_speeds = [] of Float64
        list_of_ratios = [] of Float64
        settings.round_count.times do
          beryl_speed = megabytes_per_second(message_bytesize, settings.seconds_per_arm) do
            beryl_cipher.encrypt(message, into: beryl_sealed, nonce: nonce, associated_data: associated_data)
          end
          libcrypto_speed = megabytes_per_second(message_bytesize, settings.seconds_per_arm) do
            libcrypto_cipher.encrypt(message, libcrypto_sealed, nonce, associated_data)
          end
          raise "the two arms disagree on the encrypted message" unless beryl_sealed == libcrypto_sealed

          list_of_beryl_speeds << beryl_speed
          list_of_libcrypto_speeds << libcrypto_speed
          list_of_ratios << beryl_speed / libcrypto_speed
        end

        io.puts "| {{ cipher[0].id }} | #{format_bytesize(message_bytesize)} | #{median(list_of_beryl_speeds).round(1)} | " \
                "#{median(list_of_libcrypto_speeds).round(1)} | #{describe_ratio(median(list_of_ratios))} | " \
                "#{describe_ratio(list_of_ratios.min)} to #{describe_ratio(list_of_ratios.max)} |"
        io.flush
      end
    {% end %}
  end
end

CiphersAgainstLibcrypto.run(STDOUT)
