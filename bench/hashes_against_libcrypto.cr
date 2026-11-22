# Speed of every Beryl hash and HMAC next to libcrypto's.
#
#     crystal-alpha build --release bench/hashes_against_libcrypto.cr -o hashes_against_libcrypto
#     ./hashes_against_libcrypto
#
# Method (plans/BERYL_TLS_CRYPTO.md section 3.1): both arms live in one
# binary and process the same buffer through the same streaming calls
# (`reset`, `update`, `final` into a reused buffer). They alternate, Beryl
# then libcrypto, for ten rounds; each arm of each round runs for at least
# two seconds. Each round gives one ratio, Beryl's MB/s divided by
# libcrypto's MB/s in the same round, so both sides of a ratio saw the same
# machine load. The table reports the median of those ratios and their
# paired 95% interval (Student's t on the logarithms of the ratios). Beryl is
# "at least as fast" when the whole interval is at or above 1.
#
# The HMAC arms are keyed once, outside the timing, with the same 32-byte
# key; `reset` returns each to its keyed state. libcrypto's arm is an
# `HMAC_CTX` restarted with `HMAC_Init_ex(ctx, NULL, 0, NULL, NULL)`, the
# cheapest way libcrypto offers to authenticate many messages under one key.
#
# BERYL_BENCH_ALGORITHMS picks algorithms by name, separated by commas (for
# example "SHA-256,HMAC-SHA-256"); BERYL_BENCH_SECONDS_PER_ARM and
# BERYL_BENCH_ROUNDS shorten a trial run.
require "openssl"
require "../src/beryl"

lib LibCrypto
  # The version text of the libcrypto actually loaded (`OPENSSL_VERSION` = 0).
  fun beryl_bench_openssl_version = OpenSSL_version(kind : LibC::Int) : LibC::Char*
  fun beryl_bench_hmac_ctx_new = HMAC_CTX_new : HMAC_CTX
end

module HashesAgainstLibcrypto
  LIST_OF_MESSAGE_BYTESIZES = [64, 1024, 1024 * 1024]
  BYTES_PER_MEGABYTE        = 1_000_000.0
  KEY_BYTESIZE              =          32

  # Two-sided 95% points of Student's t distribution, by degrees of freedom.
  STUDENT_T_95_PERCENT = [12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
                          2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086]

  record Settings, seconds_per_arm : Float64, round_count : Int32, list_of_algorithms : Array(String)? do
    def self.from_environment : Settings
      new(
        ENV["BERYL_BENCH_SECONDS_PER_ARM"]?.try(&.to_f) || 2.0,
        ENV["BERYL_BENCH_ROUNDS"]?.try(&.to_i) || 10,
        ENV["BERYL_BENCH_ALGORITHMS"]?.try(&.split(',').map(&.strip)),
      )
    end

    def includes_algorithm?(algorithm : String) : Bool
      selected = list_of_algorithms
      selected.nil? || selected.includes?(algorithm)
    end
  end

  # libcrypto's HMAC under one key, with the three streaming calls the
  # measurement uses.
  class LibcryptoAuthentication
    def initialize(libcrypto_name : String, key : Bytes)
      @context = LibCrypto.beryl_bench_hmac_ctx_new
      evp_md = LibCrypto.evp_get_digestbyname(libcrypto_name)
      raise "libcrypto has no digest named #{libcrypto_name}" if evp_md.null?
      if LibCrypto.hmac_init_ex(@context, key.to_unsafe.as(Void*), key.size, evp_md, Pointer(Void).null) != 1
        raise "libcrypto refused the HMAC key"
      end
    end

    def reset : Nil
      LibCrypto.hmac_init_ex(@context, Pointer(Void).null, 0, Pointer(Void).null.as(LibCrypto::EVP_MD), Pointer(Void).null)
    end

    def update(message : Bytes) : Nil
      LibCrypto.hmac_update(@context, message.to_unsafe, message.size)
    end

    def final(tag : Bytes) : Nil
      LibCrypto.hmac_final(@context, tag.to_unsafe, out _)
    end
  end

  # Processes *message* over and over for at least *seconds* and returns MB/s.
  def self.megabytes_per_second(digest, message : Bytes, output : Bytes, seconds : Float64) : Float64
    # Check the clock every so many messages that the checks cost nothing.
    messages_per_clock_check = Math.max(1, 65_536 // message.size)
    bytes_processed = 0_u64
    started_at = Time.instant
    elapsed_seconds = 0.0
    while elapsed_seconds < seconds
      messages_per_clock_check.times do
        digest.reset
        digest.update(message)
        digest.final(output)
      end
      bytes_processed += messages_per_clock_check.to_u64 * message.size
      elapsed_seconds = (Time.instant - started_at).total_seconds
    end
    bytes_processed / BYTES_PER_MEGABYTE / elapsed_seconds
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
    ratio >= 1.0 ? "#{ratio.round(2)}× as fast" : "#{(1.0 / ratio).round(2)}× slower"
  end

  def self.format_bytesize(bytesize : Int32) : String
    return "#{bytesize // (1024 * 1024)} MiB" if bytesize >= 1024 * 1024
    return "#{bytesize // 1024} KiB" if bytesize >= 1024

    "#{bytesize} B"
  end

  # Runs the rounds for one algorithm at one message size and prints its row.
  def self.measure(io : IO, settings : Settings, algorithm : String, message_bytesize : Int32, beryl_arm, libcrypto_arm, output_bytesize : Int32) : Nil
    message = Random::Secure.random_bytes(message_bytesize)
    beryl_output = Bytes.new(output_bytesize)
    libcrypto_output = Bytes.new(output_bytesize)

    list_of_beryl_speeds = [] of Float64
    list_of_libcrypto_speeds = [] of Float64
    list_of_ratios = [] of Float64
    settings.round_count.times do
      beryl_speed = megabytes_per_second(beryl_arm, message, beryl_output, settings.seconds_per_arm)
      libcrypto_speed = megabytes_per_second(libcrypto_arm, message, libcrypto_output, settings.seconds_per_arm)
      raise "the two arms disagree on #{algorithm}" unless beryl_output == libcrypto_output

      list_of_beryl_speeds << beryl_speed
      list_of_libcrypto_speeds << libcrypto_speed
      list_of_ratios << beryl_speed / libcrypto_speed
    end

    interval = paired_interval(list_of_ratios)
    io.puts "| #{algorithm} | #{format_bytesize(message_bytesize)} | #{median(list_of_beryl_speeds).round(1)} | " \
            "#{median(list_of_libcrypto_speeds).round(1)} | #{describe_ratio(median(list_of_ratios))} | " \
            "#{describe_ratio(interval[0])} to #{describe_ratio(interval[1])} | #{interval[0] >= 1.0 ? "yes" : "no"} |"
    io.flush
  end

  def self.run(io : IO) : Nil
    settings = Settings.from_environment
    key = Random::Secure.random_bytes(KEY_BYTESIZE)
    io.puts "Beryl #{Beryl::VERSION} against #{String.new(LibCrypto.beryl_bench_openssl_version(0))}"
    io.puts "#{settings.round_count} rounds, Beryl then libcrypto in each, #{settings.seconds_per_arm} s per arm"
    io.puts "SHA-1, SHA-256 and SHA-512 instructions in use by Beryl: " \
            "#{Beryl::Crypto::ProcessorFeatures::HAS_SHA1_INSTRUCTIONS}, " \
            "#{Beryl::Crypto::ProcessorFeatures::HAS_SHA256_INSTRUCTIONS}, " \
            "#{Beryl::Crypto::ProcessorFeatures::HAS_SHA512_INSTRUCTIONS}"
    io.puts
    io.puts "| Algorithm | Message | Beryl MB/s (median) | libcrypto MB/s (median) | Beryl against libcrypto (median of rounds) | Paired 95% interval | At least as fast |"
    io.puts "|---|---|---|---|---|---|---|"

    {% for hash in [{"MD5", "MD5", "Beryl::Crypto::Compatibility::MD5"},
                    {"SHA-1", "SHA1", "Beryl::Crypto::Compatibility::SHA1"},
                    {"SHA-224", "SHA224", "Beryl::Crypto::V1::SHA224"},
                    {"SHA-256", "SHA256", "Beryl::Crypto::V1::SHA256"},
                    {"SHA-384", "SHA384", "Beryl::Crypto::V1::SHA384"},
                    {"SHA-512", "SHA512", "Beryl::Crypto::V1::SHA512"},
                    {"SHA-512/256", "SHA512-256", "Beryl::Crypto::V1::SHA512_256"}] %}
      if settings.includes_algorithm?({{ hash[0] }})
        LIST_OF_MESSAGE_BYTESIZES.each do |message_bytesize|
          beryl_hash = {{ hash[2].id }}.new
          measure(io, settings, {{ hash[0] }}, message_bytesize, beryl_hash, OpenSSL::Digest.new({{ hash[1] }}), beryl_hash.digest_size)
        end
      end
      if settings.includes_algorithm?({{ "HMAC-" + hash[0] }})
        LIST_OF_MESSAGE_BYTESIZES.each do |message_bytesize|
          beryl_authentication = Beryl::Crypto::V1::HMAC({{ hash[2].id }}).new(key)
          measure(io, settings, {{ "HMAC-" + hash[0] }}, message_bytesize, beryl_authentication,
            LibcryptoAuthentication.new({{ hash[1] }}, key), beryl_authentication.digest_size)
        end
      end
    {% end %}
  end
end

HashesAgainstLibcrypto.run(STDOUT)
