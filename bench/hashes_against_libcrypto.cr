# Baseline speed of Beryl's SHA-256 and SHA-512 next to libcrypto's.
#
#     crystal-alpha build --release bench/hashes_against_libcrypto.cr -o hashes_against_libcrypto
#     ./hashes_against_libcrypto
#
# Method (plans/BERYL_TLS_CRYPTO.md section 3.1): both arms live in one
# binary and hash the same buffer through the same streaming calls (`reset`,
# `update`, `final` into a reused buffer). They alternate, Beryl then
# libcrypto, for ten rounds; each arm of each round runs for at least two
# seconds. The figure reported is the median over the rounds of
# Beryl's MB/s divided by libcrypto's MB/s in the same round.
#
# BERYL_BENCH_SECONDS_PER_ARM and BERYL_BENCH_ROUNDS shorten a trial run.
require "openssl"
require "../src/beryl"

lib LibCrypto
  # The version text of the libcrypto actually loaded (`OPENSSL_VERSION` = 0).
  fun beryl_bench_openssl_version = OpenSSL_version(kind : LibC::Int) : LibC::Char*
end

module HashesAgainstLibcrypto
  LIST_OF_MESSAGE_BYTESIZES = [64, 1024, 1024 * 1024]
  BYTES_PER_MEGABYTE        = 1_000_000.0

  record Settings, seconds_per_arm : Float64, round_count : Int32 do
    def self.from_environment : Settings
      new(
        ENV["BERYL_BENCH_SECONDS_PER_ARM"]?.try(&.to_f) || 2.0,
        ENV["BERYL_BENCH_ROUNDS"]?.try(&.to_i) || 10,
      )
    end
  end

  # Hashes *message* over and over for at least *seconds* and returns MB/s.
  def self.megabytes_per_second(digest : ::Digest, message : Bytes, output : Bytes, seconds : Float64) : Float64
    # Check the clock every so many hashes that the checks cost nothing.
    hashes_per_clock_check = Math.max(1, 65_536 // message.size)
    bytes_hashed = 0_u64
    started_at = Time.instant
    elapsed_seconds = 0.0
    while elapsed_seconds < seconds
      hashes_per_clock_check.times do
        digest.reset
        digest.update(message)
        digest.final(output)
      end
      bytes_hashed += hashes_per_clock_check.to_u64 * message.size
      elapsed_seconds = (Time.instant - started_at).total_seconds
    end
    bytes_hashed / BYTES_PER_MEGABYTE / elapsed_seconds
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
    io.puts "Beryl #{Beryl::VERSION} against #{String.new(LibCrypto.beryl_bench_openssl_version(0))}"
    io.puts "#{settings.round_count} rounds, Beryl then libcrypto in each, #{settings.seconds_per_arm} s per arm"
    io.puts
    io.puts "| Hash | Message | Beryl MB/s (median) | libcrypto MB/s (median) | Beryl against libcrypto (median of rounds) | Range over rounds |"
    io.puts "|---|---|---|---|---|---|"

    {% for hash in [{"SHA-256", "SHA256", "Beryl::Crypto::V1::SHA256"}, {"SHA-512", "SHA512", "Beryl::Crypto::V1::SHA512"}] %}
      LIST_OF_MESSAGE_BYTESIZES.each do |message_bytesize|
        message = Random::Secure.random_bytes(message_bytesize)
        beryl_hash = {{ hash[2].id }}.new
        libcrypto_hash = OpenSSL::Digest.new({{ hash[1] }})
        beryl_output = Bytes.new(beryl_hash.digest_size)
        libcrypto_output = Bytes.new(beryl_hash.digest_size)

        list_of_beryl_speeds = [] of Float64
        list_of_libcrypto_speeds = [] of Float64
        list_of_ratios = [] of Float64
        settings.round_count.times do
          beryl_speed = megabytes_per_second(beryl_hash, message, beryl_output, settings.seconds_per_arm)
          libcrypto_speed = megabytes_per_second(libcrypto_hash, message, libcrypto_output, settings.seconds_per_arm)
          raise "the two arms disagree on the digest" unless beryl_output == libcrypto_output

          list_of_beryl_speeds << beryl_speed
          list_of_libcrypto_speeds << libcrypto_speed
          list_of_ratios << beryl_speed / libcrypto_speed
        end

        io.puts "| {{ hash[0].id }} | #{format_bytesize(message_bytesize)} | #{median(list_of_beryl_speeds).round(1)} | " \
                "#{median(list_of_libcrypto_speeds).round(1)} | #{describe_ratio(median(list_of_ratios))} | " \
                "#{describe_ratio(list_of_ratios.min)} to #{describe_ratio(list_of_ratios.max)} |"
        io.flush
      end
    {% end %}
  end
end

HashesAgainstLibcrypto.run(STDOUT)
