# Speed of Beryl's ciphers next to libcrypto's.
#
#     crystal-alpha build --release bench/ciphers_against_libcrypto.cr -o ciphers_against_libcrypto
#     ./ciphers_against_libcrypto
#
# Method (plans/BERYL_TLS_CRYPTO.md section 3.1), the same as
# bench/hashes_against_libcrypto.cr: both arms live in one binary and work
# on the same message under the same key, nonce and 13 bytes of associated
# data (the size of a TLS record header), into a reused buffer. Each arm
# keeps its keyed cipher between messages, as a connection does. A row is
# ten rounds, and in a round each arm runs for at least two seconds of
# processor time (time spent waiting for a processor is not counted).
# Within a round the arms take turns of a few milliseconds (about 2 MiB of
# input each), and the arm that goes first changes every turn, so both see
# the same machine load even on a machine that is busy with other work. Each
# round gives one ratio, Beryl's MB/s divided by libcrypto's MB/s. The table
# reports the median of those ratios and their paired 95% interval
# (Student's t on the logarithms of the ratios). Beryl is "at least as
# fast" when the whole interval is at or above 1.
#
# Rows:
# - "seal" encrypts and writes the tag; "open" checks the tag and decrypts.
#   Beryl checks the tag before it writes a byte of plaintext, so its open
#   reads the message twice; libcrypto decrypts while it hashes and checks
#   the tag at the end.
# - XChaCha20-Poly1305 has no libcrypto implementation. Its row runs against
#   XChaCha20-Poly1305 built from libcrypto's parts (`LibcryptoExtendedNonceCipher`),
#   and both arms must produce the same bytes. BERYL_BENCH_XCHACHA_AGAINST=chacha20
#   runs it against plain ChaCha20-Poly1305 instead, which skips HChaCha20.
# - AES-CBC encrypts and decrypts with PKCS#7 padding, as
#   `Beryl::Crypto::Compatibility::AESCBC` does; the message size is the
#   plaintext's.
#
# BERYL_BENCH_ALGORITHMS picks rows by cipher name, separated by commas (for
# example "AES-128-GCM,ChaCha20-Poly1305"); BERYL_BENCH_SIZES picks message
# sizes in bytes; BERYL_BENCH_SECONDS_PER_ARM and BERYL_BENCH_ROUNDS shorten
# a trial run.
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
  ASSOCIATED_DATA_BYTESIZE  =          13
  EVP_CTRL_AEAD_SET_IVLEN   =         0x9
  EVP_CTRL_AEAD_GET_TAG     =        0x10
  EVP_CTRL_AEAD_SET_TAG     =        0x11

  # Two-sided 95% points of Student's t distribution, by degrees of freedom.
  STUDENT_T_95_PERCENT = [12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
                          2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086]

  record Settings, seconds_per_arm : Float64, round_count : Int32, list_of_algorithms : Array(String)?,
    list_of_message_bytesizes : Array(Int32) do
    def self.from_environment : Settings
      new(
        ENV["BERYL_BENCH_SECONDS_PER_ARM"]?.try(&.to_f) || 2.0,
        ENV["BERYL_BENCH_ROUNDS"]?.try(&.to_i) || 10,
        ENV["BERYL_BENCH_ALGORITHMS"]?.try(&.split(',').map(&.strip)),
        ENV["BERYL_BENCH_SIZES"]?.try(&.split(',').map(&.strip.to_i)) || LIST_OF_MESSAGE_BYTESIZES,
      )
    end

    def includes_algorithm?(algorithm : String) : Bool
      selected = list_of_algorithms
      selected.nil? || selected.includes?(algorithm)
    end
  end

  # libcrypto's cipher, keyed once and reused for every message.
  class LibcryptoCipher
    @is_authenticated : Bool
    @direction : LibC::Int

    def initialize(libcrypto_name : String, key : Bytes, is_sealing : Bool)
      cipher = LibCrypto.evp_get_cipherbyname(libcrypto_name)
      raise "libcrypto has no cipher named #{libcrypto_name}" if cipher.null?
      @is_authenticated = !libcrypto_name.includes?("cbc")
      @context = LibCrypto.evp_cipher_ctx_new
      direction = @direction = is_sealing ? 1 : 0
      check LibCrypto.evp_cipherinit_ex(@context, cipher, Pointer(Void).null, Pointer(UInt8).null, Pointer(UInt8).null, direction)
      check LibCrypto.beryl_cipher_bench_evp_cipher_ctx_ctrl(@context, EVP_CTRL_AEAD_SET_IVLEN, 12, Pointer(Void).null) if @is_authenticated
      check LibCrypto.evp_cipherinit_ex(@context, Pointer(Void).null.as(LibCrypto::EVP_CIPHER), Pointer(Void).null, key, Pointer(UInt8).null, direction)
    end

    # Encrypts *message* into *sealed*: the ciphertext and the tag, or the
    # padded ciphertext for CBC. Returns the bytes written.
    def seal(message : Bytes, sealed : Bytes, nonce : Bytes, associated_data : Bytes) : Int32
      written = 0
      check LibCrypto.evp_cipherinit_ex(@context, Pointer(Void).null.as(LibCrypto::EVP_CIPHER), Pointer(Void).null, Pointer(UInt8).null, nonce, -1)
      check LibCrypto.evp_cipherupdate(@context, Pointer(UInt8).null, pointerof(written), associated_data, associated_data.size) if @is_authenticated
      check LibCrypto.evp_cipherupdate(@context, sealed, pointerof(written), message, message.size)
      total = written
      check LibCrypto.evp_cipherfinal_ex(@context, sealed.to_unsafe + total, pointerof(written))
      total += written
      if @is_authenticated
        check LibCrypto.beryl_cipher_bench_evp_cipher_ctx_ctrl(@context, EVP_CTRL_AEAD_GET_TAG, TAG_BYTESIZE, (sealed.to_unsafe + total).as(Void*))
        total += TAG_BYTESIZE
      end
      total
    end

    # Decrypts *sealed* into *opened* and checks the tag or the padding.
    # Returns the bytes of plaintext.
    def open(sealed : Bytes, opened : Bytes, nonce : Bytes, associated_data : Bytes) : Int32
      written = 0
      body_bytesize = @is_authenticated ? sealed.size - TAG_BYTESIZE : sealed.size
      check LibCrypto.evp_cipherinit_ex(@context, Pointer(Void).null.as(LibCrypto::EVP_CIPHER), Pointer(Void).null, Pointer(UInt8).null, nonce, -1)
      if @is_authenticated
        check LibCrypto.beryl_cipher_bench_evp_cipher_ctx_ctrl(@context, EVP_CTRL_AEAD_SET_TAG, TAG_BYTESIZE, (sealed.to_unsafe + body_bytesize).as(Void*))
        check LibCrypto.evp_cipherupdate(@context, Pointer(UInt8).null, pointerof(written), associated_data, associated_data.size)
      end
      check LibCrypto.evp_cipherupdate(@context, opened, pointerof(written), sealed, body_bytesize)
      total = written
      check LibCrypto.evp_cipherfinal_ex(@context, opened.to_unsafe + total, pointerof(written))
      total + written
    end

    # Replaces the key, keeping the cipher and the nonce size.
    def rekey(key : Bytes) : Nil
      check LibCrypto.evp_cipherinit_ex(@context, Pointer(Void).null.as(LibCrypto::EVP_CIPHER), Pointer(Void).null, key, Pointer(UInt8).null, @direction)
    end

    private def check(result : LibC::Int) : Nil
      raise "a libcrypto cipher call failed" unless result == 1
    end
  end

  # XChaCha20-Poly1305 as a program on libcrypto has to build it: libcrypto
  # has HChaCha20 only inside one block of its raw ChaCha20, whose words 0
  # to 3 and 12 to 15, less the input words (the constants and the first 16
  # nonce bytes, all public), are HChaCha20's output. That subkey then keys
  # libcrypto's ChaCha20-Poly1305, with the last 8 nonce bytes.
  class LibcryptoExtendedNonceCipher
    CONSTANT_WORDS = {0x61707865_u32, 0x3320646e_u32, 0x79622d32_u32, 0x6b206574_u32}

    @key : Bytes
    @inner : LibcryptoCipher

    def initialize(key : Bytes, is_sealing : Bool)
      @key = key.dup
      @inner = LibcryptoCipher.new("chacha20-poly1305", key, is_sealing)
      @stream_cipher = LibCrypto.evp_get_cipherbyname("chacha20")
      raise "libcrypto has no cipher named chacha20" if @stream_cipher.null?
      @stream_context = LibCrypto.evp_cipher_ctx_new
      @zero_block = Bytes.new(64)
      @block = Bytes.new(64)
      @subkey = Bytes.new(32)
      @inner_nonce = Bytes.new(12)
    end

    def seal(message : Bytes, sealed : Bytes, nonce : Bytes, associated_data : Bytes) : Int32
      derive_subkey(nonce)
      @inner.seal(message, sealed, @inner_nonce, associated_data)
    end

    def open(sealed : Bytes, opened : Bytes, nonce : Bytes, associated_data : Bytes) : Int32
      derive_subkey(nonce)
      @inner.open(sealed, opened, @inner_nonce, associated_data)
    end

    private def derive_subkey(nonce : Bytes) : Nil
      written = 0
      check LibCrypto.evp_cipherinit_ex(@stream_context, @stream_cipher, Pointer(Void).null, @key, nonce, 1)
      check LibCrypto.evp_cipherupdate(@stream_context, @block, pointerof(written), @zero_block, 64)
      4.times do |index|
        word = IO::ByteFormat::LittleEndian.decode(UInt32, @block[4 * index, 4]) &- CONSTANT_WORDS[index]
        IO::ByteFormat::LittleEndian.encode(word, @subkey[4 * index, 4])
        word = IO::ByteFormat::LittleEndian.decode(UInt32, @block[48 + 4 * index, 4]) &-
               IO::ByteFormat::LittleEndian.decode(UInt32, nonce[4 * index, 4])
        IO::ByteFormat::LittleEndian.encode(word, @subkey[16 + 4 * index, 4])
      end
      @inner.rekey(@subkey)
      nonce[16, 8].copy_to(@inner_nonce + 4)
    end

    private def check(result : LibC::Int) : Nil
      raise "a libcrypto cipher call failed" unless result == 1
    end
  end

  # `CLOCK_THREAD_CPUTIME_ID` of <time.h>.
  THREAD_PROCESSOR_TIME_CLOCK = {% if flag?(:darwin) %} 16 {% else %} 3 {% end %}

  # Returns the processor time this thread has used, in seconds. Time the
  # thread spent waiting for a processor is left out, so other work on the
  # machine does not count against either arm.
  def self.processor_seconds : Float64
    if LibC.clock_gettime(LibC::ClockidT.new(THREAD_PROCESSOR_TIME_CLOCK), out time) != 0
      raise RuntimeError.from_errno("clock_gettime")
    end
    time.tv_sec.to_f64 + time.tv_nsec.to_f64 / 1_000_000_000
  end

  # About this many bytes go through one arm before the other arm takes its
  # turn: a few milliseconds of work.
  BYTES_PER_TURN = 2 * 1024 * 1024

  # Runs one round: the two arms take turns of a few milliseconds each on
  # messages of *message_bytesize* until each has run for at least
  # *seconds_per_arm*, and the arm that goes first changes every turn.
  # Returns each arm's MB per second of processor time over its own turns.
  def self.megabytes_per_second_of_each_arm(message_bytesize : Int32, seconds_per_arm : Float64,
                                            beryl_arm : Proc(Nil), libcrypto_arm : Proc(Nil)) : {Float64, Float64}
    messages_per_turn = Math.max(1, BYTES_PER_TURN // message_bytesize)
    bytes_per_turn = messages_per_turn.to_u64 * message_bytesize
    bytes_processed = 0_u64
    beryl_seconds = 0.0
    libcrypto_seconds = 0.0
    beryl_goes_first = true
    while beryl_seconds < seconds_per_arm || libcrypto_seconds < seconds_per_arm
      first_arm, second_arm = beryl_goes_first ? {beryl_arm, libcrypto_arm} : {libcrypto_arm, beryl_arm}
      started_at = processor_seconds
      messages_per_turn.times { first_arm.call }
      changed_at = processor_seconds
      messages_per_turn.times { second_arm.call }
      finished_at = processor_seconds

      first_seconds = changed_at - started_at
      second_seconds = finished_at - changed_at
      beryl_seconds += beryl_goes_first ? first_seconds : second_seconds
      libcrypto_seconds += beryl_goes_first ? second_seconds : first_seconds
      bytes_processed += bytes_per_turn
      beryl_goes_first = !beryl_goes_first
    end
    megabytes = bytes_processed / BYTES_PER_MEGABYTE
    {megabytes / beryl_seconds, megabytes / libcrypto_seconds}
  end

  def self.median(list_of_values : Array(Float64)) : Float64
    sorted = list_of_values.sort
    middle = sorted.size // 2
    sorted.size.odd? ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2
  end

  # Returns the paired 95% interval of the ratio: the interval of the mean of
  # the logarithms of the per-round ratios, turned back into a ratio.
  def self.paired_interval(list_of_ratios : Array(Float64)) : {Float64, Float64}
    return {list_of_ratios[0], list_of_ratios[0]} if list_of_ratios.size < 2

    list_of_logarithms = list_of_ratios.map { |ratio| Math.log(ratio) }
    mean = list_of_logarithms.sum / list_of_logarithms.size
    variance = list_of_logarithms.sum { |logarithm| (logarithm - mean) ** 2 } / (list_of_logarithms.size - 1)
    degrees_of_freedom = list_of_logarithms.size - 1
    student_t = STUDENT_T_95_PERCENT[degrees_of_freedom - 1]? || 1.96
    half_width = student_t * Math.sqrt(variance / list_of_logarithms.size)
    {Math.exp(mean - half_width), Math.exp(mean + half_width)}
  end

  # States a ratio of Beryl's speed to libcrypto's the way Seth reads it.
  def self.describe_ratio(ratio : Float64) : String
    # Three decimals near 1, where the second would hide which side it is on.
    factor = ratio >= 1.0 ? ratio : 1.0 / ratio
    rounded = factor < 1.1 ? factor.round(3) : factor.round(2)
    ratio >= 1.0 ? "#{rounded}× as fast" : "#{rounded}× slower"
  end

  def self.format_bytesize(bytesize : Int32) : String
    return "#{bytesize // (1024 * 1024)} MiB" if bytesize >= 1024 * 1024
    return "#{bytesize // 1024} KiB" if bytesize >= 1024

    "#{bytesize} B"
  end

  # Runs the rounds for one row and prints it.
  def self.measure(io : IO, settings : Settings, algorithm : String, direction : String, message_bytesize : Int32,
                   beryl_arm : Proc(Nil), libcrypto_arm : Proc(Nil)) : Nil
    list_of_beryl_speeds = [] of Float64
    list_of_libcrypto_speeds = [] of Float64
    list_of_ratios = [] of Float64
    settings.round_count.times do
      beryl_speed, libcrypto_speed = megabytes_per_second_of_each_arm(message_bytesize, settings.seconds_per_arm, beryl_arm, libcrypto_arm)
      list_of_beryl_speeds << beryl_speed
      list_of_libcrypto_speeds << libcrypto_speed
      list_of_ratios << beryl_speed / libcrypto_speed
    end

    interval = paired_interval(list_of_ratios)
    io.puts "| #{algorithm} | #{direction} | #{format_bytesize(message_bytesize)} | #{median(list_of_beryl_speeds).round(1)} | " \
            "#{median(list_of_libcrypto_speeds).round(1)} | #{describe_ratio(median(list_of_ratios))} | " \
            "#{describe_ratio(interval[0])} to #{describe_ratio(interval[1])} | #{interval[0] >= 1.0 ? "yes" : "no"} |"
    io.flush
  end

  def self.new_authenticated_arm(libcrypto_name : String, key : Bytes, is_sealing : Bool) : LibcryptoCipher | LibcryptoExtendedNonceCipher
    if libcrypto_name == "xchacha20-poly1305"
      LibcryptoExtendedNonceCipher.new(key, is_sealing)
    else
      LibcryptoCipher.new(libcrypto_name, key, is_sealing)
    end
  end

  # Measures sealing and opening of one authenticated cipher at one size.
  # *libcrypto_name* is the cipher libcrypto runs against it.
  def self.measure_authenticated_cipher(io : IO, settings : Settings, algorithm : String, libcrypto_name : String,
                                        beryl_cipher : Beryl::Crypto::V1::AuthenticatedEncryption, key : Bytes,
                                        message_bytesize : Int32) : Nil
    beryl_nonce = Random::Secure.random_bytes(beryl_cipher.nonce_bytesize)
    libcrypto_name = "chacha20-poly1305" if libcrypto_name == "xchacha20-poly1305" && ENV["BERYL_BENCH_XCHACHA_AGAINST"]? == "chacha20"
    libcrypto_nonce = libcrypto_name == "xchacha20-poly1305" ? beryl_nonce : Random::Secure.random_bytes(12)
    associated_data = Random::Secure.random_bytes(ASSOCIATED_DATA_BYTESIZE)
    message = Random::Secure.random_bytes(message_bytesize)
    libcrypto_sealing = new_authenticated_arm(libcrypto_name, key, true)
    libcrypto_opening = new_authenticated_arm(libcrypto_name, key, false)
    beryl_sealed = Bytes.new(message_bytesize + TAG_BYTESIZE)
    libcrypto_sealed = Bytes.new(message_bytesize + TAG_BYTESIZE)
    beryl_opened = Bytes.new(message_bytesize)
    libcrypto_opened = Bytes.new(message_bytesize)

    # Both arms must produce the same bytes before either is timed.
    beryl_cipher.encrypt(message, into: beryl_sealed, nonce: beryl_nonce, associated_data: associated_data)
    libcrypto_sealing.seal(message, libcrypto_sealed, libcrypto_nonce, associated_data)
    if beryl_nonce.size == libcrypto_nonce.size
      check_cipher = beryl_cipher.class.new(key)
      raise "the two arms disagree on #{algorithm}" unless check_cipher.encrypt(message, nonce: libcrypto_nonce, associated_data: associated_data) == libcrypto_sealed
    end
    raise "Beryl cannot open its own #{algorithm} message" unless beryl_cipher.decrypt(beryl_sealed, into: beryl_opened, nonce: beryl_nonce, associated_data: associated_data)
    raise "Beryl opened #{algorithm} to other bytes" unless beryl_opened == message

    if settings.includes_algorithm?(algorithm)
      measure(io, settings, algorithm, "seal", message_bytesize,
        -> { beryl_cipher.encrypt(message, into: beryl_sealed, nonce: beryl_nonce, associated_data: associated_data); nil },
        -> { libcrypto_sealing.seal(message, libcrypto_sealed, libcrypto_nonce, associated_data); nil })
      measure(io, settings, algorithm, "open", message_bytesize,
        -> { beryl_cipher.decrypt(beryl_sealed, into: beryl_opened, nonce: beryl_nonce, associated_data: associated_data); nil },
        -> { libcrypto_opening.open(libcrypto_sealed, libcrypto_opened, libcrypto_nonce, associated_data); nil })
    end
  end

  # Measures AES-CBC with PKCS#7 padding at one size, both directions.
  def self.measure_chained_cipher(io : IO, settings : Settings, algorithm : String, libcrypto_name : String, key : Bytes,
                                  message_bytesize : Int32) : Nil
    initialization_vector = Random::Secure.random_bytes(16)
    message = Random::Secure.random_bytes(message_bytesize)
    beryl_cipher = Beryl::Crypto::Compatibility::AESCBC.new(key)
    libcrypto_sealing = LibcryptoCipher.new(libcrypto_name, key, true)
    libcrypto_opening = LibcryptoCipher.new(libcrypto_name, key, false)
    padded_bytesize = message_bytesize + 16 - message_bytesize % 16
    libcrypto_sealed = Bytes.new(padded_bytesize)
    libcrypto_opened = Bytes.new(padded_bytesize + 16)
    beryl_sealed = beryl_cipher.encrypt(message, initialization_vector: initialization_vector)
    libcrypto_sealing.seal(message, libcrypto_sealed, initialization_vector, Bytes.empty)
    raise "the two arms disagree on #{algorithm}" unless beryl_sealed == libcrypto_sealed
    raise "Beryl cannot open its own #{algorithm} message" unless beryl_cipher.decrypt(beryl_sealed, initialization_vector: initialization_vector) == message

    beryl_written = Bytes.new(padded_bytesize)
    measure(io, settings, algorithm, "seal", message_bytesize,
      -> { beryl_cipher.encrypt(message, into: beryl_written, initialization_vector: initialization_vector); nil },
      -> { libcrypto_sealing.seal(message, libcrypto_sealed, initialization_vector, Bytes.empty); nil })
    measure(io, settings, algorithm, "open", message_bytesize,
      -> { beryl_cipher.decrypt(beryl_sealed, into: beryl_written, initialization_vector: initialization_vector); nil },
      -> { libcrypto_opening.open(libcrypto_sealed, libcrypto_opened, initialization_vector, Bytes.empty); nil })
  end

  def self.run(io : IO) : Nil
    settings = Settings.from_environment
    io.puts "Beryl #{Beryl::VERSION} against #{String.new(LibCrypto.beryl_cipher_bench_openssl_version(0))}"
    io.puts "#{settings.round_count} rounds, #{settings.seconds_per_arm} s of processor time per arm in each, the arms taking turns of about 2 MiB of input"
    io.puts "AES, carry-less multiply and vector instructions in use by Beryl: " \
            "#{Beryl::Crypto::ProcessorFeatures::HAS_AES_INSTRUCTIONS}, " \
            "#{Beryl::Crypto::ProcessorFeatures::HAS_CARRYLESS_MULTIPLY_INSTRUCTIONS}, " \
            "#{Beryl::Crypto::ProcessorFeatures::HAS_VECTOR_INSTRUCTIONS}"
    io.puts
    io.puts "| Cipher | Direction | Message | Beryl MB/s (median) | libcrypto MB/s (median) | Beryl against libcrypto (median of rounds) | Paired 95% interval | At least as fast |"
    io.puts "|---|---|---|---|---|---|---|---|"

    {% for cipher in [{"ChaCha20-Poly1305", "chacha20-poly1305", 32, "Beryl::Crypto::V1::ChaCha20Poly1305"},
                      {"XChaCha20-Poly1305", "xchacha20-poly1305", 32, "Beryl::Crypto::V1::XChaCha20Poly1305"},
                      {"AES-128-GCM", "aes-128-gcm", 16, "Beryl::Crypto::V1::AESGCM"},
                      {"AES-256-GCM", "aes-256-gcm", 32, "Beryl::Crypto::V1::AESGCM"}] %}
      if settings.includes_algorithm?({{ cipher[0] }})
        settings.list_of_message_bytesizes.each do |message_bytesize|
          key = Random::Secure.random_bytes({{ cipher[2] }})
          measure_authenticated_cipher(io, settings, {{ cipher[0] }}, {{ cipher[1] }}, {{ cipher[3].id }}.new(key), key, message_bytesize)
        end
      end
    {% end %}
    {% for cipher in [{"AES-128-CBC", "aes-128-cbc", 16}, {"AES-256-CBC", "aes-256-cbc", 32}] %}
      if settings.includes_algorithm?({{ cipher[0] }})
        settings.list_of_message_bytesizes.each do |message_bytesize|
          measure_chained_cipher(io, settings, {{ cipher[0] }}, {{ cipher[1] }}, Random::Secure.random_bytes({{ cipher[2] }}), message_bytesize)
        end
      end
    {% end %}
  end
end

CiphersAgainstLibcrypto.run(STDOUT)
