# Speed of every Beryl hash and HMAC next to libcrypto's.
#
#     crystal-alpha build --release bench/hashes_against_libcrypto.cr -o hashes_against_libcrypto
#     ./hashes_against_libcrypto
#
# Method (plans/BERYL_TLS_CRYPTO.md section 3.1): both arms live in one
# binary and process the same buffer through the same streaming calls
# (`reset`, `update`, `final` into a reused buffer). A row is ten rounds, and
# in a round each arm runs for at least two seconds of processor time (time
# spent waiting for a processor is not counted). Within a round the arms
# take turns of a few milliseconds (about 2 MiB of input each), and the arm
# that goes first changes every turn, so both see the same machine load even
# on a machine that is busy with other work. Each round gives one ratio,
# Beryl's MB/s divided by libcrypto's MB/s. The table reports the median of
# those ratios and their paired 95% interval (Student's t on the logarithms
# of the ratios). Beryl is "at least as fast" when the whole interval is at
# or above 1.
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

  # Runs one round: the two arms take turns of a few milliseconds each on the
  # same *message* until each has run for at least *seconds_per_arm*, and the
  # arm that goes first changes every turn. Returns each arm's MB per second
  # of processor time over its own turns. Turns this short put both arms
  # under the same machine load, which whole seconds apart on a shared
  # machine do not.
  def self.megabytes_per_second_of_each_arm(beryl_arm, libcrypto_arm, message : Bytes, beryl_output : Bytes,
                                            libcrypto_output : Bytes, seconds_per_arm : Float64) : {Float64, Float64}
    messages_per_turn = Math.max(1, BYTES_PER_TURN // message.size)
    bytes_per_turn = messages_per_turn.to_u64 * message.size
    bytes_processed = 0_u64
    beryl_seconds = 0.0
    libcrypto_seconds = 0.0
    beryl_goes_first = true
    while beryl_seconds < seconds_per_arm || libcrypto_seconds < seconds_per_arm
      started_at = processor_seconds
      if beryl_goes_first
        messages_per_turn.times { beryl_arm.reset; beryl_arm.update(message); beryl_arm.final(beryl_output) }
      else
        messages_per_turn.times { libcrypto_arm.reset; libcrypto_arm.update(message); libcrypto_arm.final(libcrypto_output) }
      end
      changed_at = processor_seconds
      if beryl_goes_first
        messages_per_turn.times { libcrypto_arm.reset; libcrypto_arm.update(message); libcrypto_arm.final(libcrypto_output) }
      else
        messages_per_turn.times { beryl_arm.reset; beryl_arm.update(message); beryl_arm.final(beryl_output) }
      end
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

  # Runs the rounds for one algorithm at one message size and prints its row.
  def self.measure(io : IO, settings : Settings, algorithm : String, message_bytesize : Int32, beryl_arm, libcrypto_arm, output_bytesize : Int32) : Nil
    message = Random::Secure.random_bytes(message_bytesize)
    beryl_output = Bytes.new(output_bytesize)
    libcrypto_output = Bytes.new(output_bytesize)

    list_of_beryl_speeds = [] of Float64
    list_of_libcrypto_speeds = [] of Float64
    list_of_ratios = [] of Float64
    settings.round_count.times do
      beryl_speed, libcrypto_speed = megabytes_per_second_of_each_arm(
        beryl_arm, libcrypto_arm, message, beryl_output, libcrypto_output, settings.seconds_per_arm
      )
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
    io.puts "#{settings.round_count} rounds, #{settings.seconds_per_arm} s of processor time per arm in each, the arms taking turns of about 2 MiB of input"
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
