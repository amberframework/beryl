# Speed of Beryl's certificate reading and chain verification next to
# libcrypto's (OpenSSL).
#
#     crystal-alpha build --release bench/certificates_against_libcrypto.cr -o certificates_against_libcrypto
#     ./certificates_against_libcrypto
#
# Method (plans/BERYL_TLS_CRYPTO.md section 3.1), the same as the other
# benchmarks: both arms live in one binary and work on the same inputs. A
# row is ten rounds, and in a round each arm runs for at least two seconds
# of processor time. Within a round the arms take turns of about five
# milliseconds, the arm that goes first changing every turn. Each round
# gives one ratio, Beryl's operations per second divided by libcrypto's; the
# table reports the median ratio and its paired 95% interval.
#
# Inputs come from the Certificate Transparency corpus
# (scripts/fetch_certificate_corpus.rb).
#
# Rows:
# - "read 256 certificates, public keys decoded": the first 256 distinct
#   certificates of the corpus, each read and its public key decoded.
#   Beryl: `Certificate.new` and `verification_key`. libcrypto: `d2i_X509`
#   (which decodes the key) and `X509_get_extension_flags` (which decodes
#   the extensions), then `X509_free`.
# - "read 256 certificates, Beryl leaving keys until used": the same, with
#   Beryl's `Certificate.new` alone (it decodes a key when a signature is
#   first checked with it).
# - "verify chain": one logged chain verified against the Mozilla root set
#   at the log time, with the host name checked, the certificates read once
#   beforehand. Beryl: `ChainVerification#verify`. libcrypto: a new
#   `X509_STORE_CTX` on a store holding the same roots, `X509_verify_cert`
#   with purpose sslserver and the host set. Rows for a chain whose leaf is
#   signed with ECDSA and one signed with RSA.
#
# BERYL_BENCH_SECONDS_PER_ARM and BERYL_BENCH_ROUNDS shorten a trial run.
require "openssl"
require "../src/beryl"
require "../spec/fuzz/certificate_corpus"

lib LibCrypto
  fun beryl_certificate_bench_d2i_x509 = d2i_X509(a : X509*, ppin : UInt8**, length : Long) : X509
  fun beryl_certificate_bench_x509_free = X509_free(a : X509)
  fun beryl_certificate_bench_get_extension_flags = X509_get_extension_flags(certificate : X509) : UInt32
  fun beryl_certificate_bench_store_new = X509_STORE_new : X509_STORE
  fun beryl_certificate_bench_store_add_cert = X509_STORE_add_cert(ctx : X509_STORE, x : X509) : Int
  fun beryl_certificate_bench_store_ctx_new = X509_STORE_CTX_new : X509_STORE_CTX
  fun beryl_certificate_bench_store_ctx_free = X509_STORE_CTX_free(context : X509_STORE_CTX)
  fun beryl_certificate_bench_store_ctx_init = X509_STORE_CTX_init(context : X509_STORE_CTX, store : X509_STORE, leaf : X509, chain : Void*) : Int
  fun beryl_certificate_bench_store_ctx_get0_param = X509_STORE_CTX_get0_param(context : X509_STORE_CTX) : X509VerifyParam
  fun beryl_certificate_bench_verify_cert = X509_verify_cert(x : X509_STORE_CTX) : Int
  fun beryl_certificate_bench_param_set_time = X509_VERIFY_PARAM_set_time(parameters : X509VerifyParam, time : LibC::TimeT)
  fun beryl_certificate_bench_param_set1_host = X509_VERIFY_PARAM_set1_host(param : X509VerifyParam, name : UInt8*, len : SizeT) : Int
  fun beryl_certificate_bench_param_set_purpose = X509_VERIFY_PARAM_set_purpose(parameters : X509VerifyParam, purpose : Int) : Int
  fun beryl_certificate_bench_sk_new_null = OPENSSL_sk_new_null : Void*
  fun beryl_certificate_bench_sk_push = OPENSSL_sk_push(stack : Void*, item : Void*) : Int
  fun beryl_certificate_bench_openssl_version = OpenSSL_version(kind : LibC::Int) : LibC::Char*
end

module CertificatesAgainstLibcrypto
  PARSE_BATCH_SIZE   =   256
  PURPOSE_SSL_SERVER =     2
  SECONDS_PER_TURN   = 0.005

  record Settings, seconds_per_arm : Float64, round_count : Int32 do
    def self.from_environment : Settings
      new(ENV["BERYL_BENCH_SECONDS_PER_ARM"]?.try(&.to_f) || 2.0, ENV["BERYL_BENCH_ROUNDS"]?.try(&.to_i) || 10)
    end
  end

  # Two-sided 95% points of Student's t distribution, by degrees of freedom.
  STUDENT_T_95_PERCENT = [12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
                          2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086]

  # `CLOCK_THREAD_CPUTIME_ID` of <time.h>.
  THREAD_PROCESSOR_TIME_CLOCK = {% if flag?(:darwin) %} 16 {% else %} 3 {% end %}

  # Returns the processor time this thread has used, in seconds.
  def self.processor_seconds : Float64
    if LibC.clock_gettime(LibC::ClockidT.new(THREAD_PROCESSOR_TIME_CLOCK), out time) != 0
      raise RuntimeError.from_errno("clock_gettime")
    end
    time.tv_sec.to_f64 + time.tv_nsec.to_f64 / 1_000_000_000
  end

  # Returns how many calls of the slower arm fit in about one turn.
  def self.operations_per_turn(beryl_arm : Proc(Nil), libcrypto_arm : Proc(Nil)) : Int32
    started_at = processor_seconds
    beryl_arm.call
    libcrypto_arm.call
    seconds_per_pair = Math.max(processor_seconds - started_at, 1e-7)
    Math.max(1, (2 * SECONDS_PER_TURN / seconds_per_pair).to_i)
  end

  # Runs one round, the two arms taking turns until each has run for at
  # least *seconds_per_arm*. Returns each arm's operations per second.
  def self.operations_per_second_of_each_arm(seconds_per_arm : Float64, operations_per_turn : Int32,
                                             beryl_arm : Proc(Nil), libcrypto_arm : Proc(Nil)) : {Float64, Float64}
    operations = 0_i64
    beryl_seconds = 0.0
    libcrypto_seconds = 0.0
    beryl_goes_first = true
    while beryl_seconds < seconds_per_arm || libcrypto_seconds < seconds_per_arm
      first_arm, second_arm = beryl_goes_first ? {beryl_arm, libcrypto_arm} : {libcrypto_arm, beryl_arm}
      started_at = processor_seconds
      operations_per_turn.times { first_arm.call }
      changed_at = processor_seconds
      operations_per_turn.times { second_arm.call }
      finished_at = processor_seconds

      first_seconds = changed_at - started_at
      second_seconds = finished_at - changed_at
      beryl_seconds += beryl_goes_first ? first_seconds : second_seconds
      libcrypto_seconds += beryl_goes_first ? second_seconds : first_seconds
      operations += operations_per_turn
      beryl_goes_first = !beryl_goes_first
    end
    {operations / beryl_seconds, operations / libcrypto_seconds}
  end

  def self.median(list_of_values : Array(Float64)) : Float64
    sorted = list_of_values.sort
    middle = sorted.size // 2
    sorted.size.odd? ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2
  end

  # Returns the paired 95% interval of the ratio.
  def self.paired_interval(list_of_ratios : Array(Float64)) : {Float64, Float64}
    return {list_of_ratios[0], list_of_ratios[0]} if list_of_ratios.size < 2

    list_of_logarithms = list_of_ratios.map { |ratio| Math.log(ratio) }
    mean = list_of_logarithms.sum / list_of_logarithms.size
    variance = list_of_logarithms.sum { |logarithm| (logarithm - mean) ** 2 } / (list_of_logarithms.size - 1)
    student_t = STUDENT_T_95_PERCENT[list_of_logarithms.size - 2]? || 1.96
    half_width = student_t * Math.sqrt(variance / list_of_logarithms.size)
    {Math.exp(mean - half_width), Math.exp(mean + half_width)}
  end

  # States a ratio of Beryl's speed to libcrypto's as "N× as fast" or "N× slower".
  def self.describe_ratio(ratio : Float64) : String
    factor = ratio >= 1.0 ? ratio : 1.0 / ratio
    rounded = factor < 1.1 ? factor.round(3) : factor.round(2)
    ratio >= 1.0 ? "#{rounded}× as fast" : "#{rounded}× slower"
  end

  # Runs the rounds for one row and prints it.
  def self.measure(io : IO, settings : Settings, algorithm : String, operation : String,
                   beryl_arm : Proc(Nil), libcrypto_arm : Proc(Nil)) : Nil
    operations_per_turn = operations_per_turn(beryl_arm, libcrypto_arm)
    list_of_beryl_speeds = [] of Float64
    list_of_libcrypto_speeds = [] of Float64
    list_of_ratios = [] of Float64
    settings.round_count.times do
      beryl_speed, libcrypto_speed = operations_per_second_of_each_arm(settings.seconds_per_arm, operations_per_turn, beryl_arm, libcrypto_arm)
      list_of_beryl_speeds << beryl_speed
      list_of_libcrypto_speeds << libcrypto_speed
      list_of_ratios << beryl_speed / libcrypto_speed
    end

    interval = paired_interval(list_of_ratios)
    io.puts "| #{algorithm} | #{operation} | #{median(list_of_beryl_speeds).round.to_i} | #{median(list_of_libcrypto_speeds).round.to_i} | " \
            "#{describe_ratio(median(list_of_ratios))} | #{describe_ratio(interval[0])} to #{describe_ratio(interval[1])} | " \
            "#{interval[0] >= 1.0 ? "yes" : "no"} |"
    io.flush
  end

  def self.openssl_certificate(der : Bytes) : LibCrypto::X509
    pointer = der.to_unsafe
    certificate = LibCrypto.beryl_certificate_bench_d2i_x509(nil, pointerof(pointer), der.size)
    raise "libcrypto could not read a certificate" if certificate.null?
    certificate
  end

  def self.measure_parse(io : IO, settings : Settings, list_of_certificates : Array(Bytes)) : Nil
    batch = list_of_certificates.first(PARSE_BATCH_SIZE)
    beryl_arm = -> do
      batch.each { |der| Beryl::Certificates::Certificate.new(der).subject_public_key_info.verification_key }
      nil
    end
    libcrypto_arm = -> do
      batch.each do |der|
        certificate = openssl_certificate(der)
        LibCrypto.beryl_certificate_bench_get_extension_flags(certificate)
        LibCrypto.beryl_certificate_bench_x509_free(certificate)
      end
      nil
    end
    measure(io, settings, "X.509", "read #{PARSE_BATCH_SIZE} certificates, public keys decoded", beryl_arm, libcrypto_arm)

    # Beryl decodes a certificate's key when it is first used (to verify
    # a signature); `d2i_X509` still decodes every key here.
    reading_arm = -> do
      batch.each { |der| Beryl::Certificates::Certificate.new(der) }
      nil
    end
    measure(io, settings, "X.509", "read #{PARSE_BATCH_SIZE} certificates, Beryl leaving keys until used", reading_arm, libcrypto_arm)
  end

  def self.measure_verify(io : IO, settings : Settings, label : String, entry : CertificateCorpus::Entry, store : LibCrypto::X509_STORE) : Nil
    leaf = Beryl::Certificates::Certificate.new(entry.list_of_certificates.first)
    intermediates = entry.list_of_certificates[1..].map { |der| Beryl::Certificates::Certificate.new(der) }
    host = leaf.list_of_dns_names.find { |name| !name.starts_with?("*") } || raise "the chain's leaf has no plain DNS name"
    identity = Beryl::Certificates::ServiceIdentity.new(host)
    verification = Beryl::Certificates::ChainVerification.new(Beryl::Certificates::TrustStore.mozilla)
    verification.verify(leaf, intermediates, identity: identity, time: entry.timestamp)

    openssl_leaf = openssl_certificate(entry.list_of_certificates.first)
    chain = LibCrypto.beryl_certificate_bench_sk_new_null
    entry.list_of_certificates[1..].each { |der| LibCrypto.beryl_certificate_bench_sk_push(chain, openssl_certificate(der).as(Void*)) }
    libcrypto_arm = -> do
      context = LibCrypto.beryl_certificate_bench_store_ctx_new
      LibCrypto.beryl_certificate_bench_store_ctx_init(context, store, openssl_leaf, chain)
      parameters = LibCrypto.beryl_certificate_bench_store_ctx_get0_param(context)
      LibCrypto.beryl_certificate_bench_param_set_time(parameters, entry.timestamp.to_unix)
      LibCrypto.beryl_certificate_bench_param_set_purpose(parameters, PURPOSE_SSL_SERVER)
      LibCrypto.beryl_certificate_bench_param_set1_host(parameters, host.to_unsafe, host.bytesize)
      raise "libcrypto refused the chain" unless LibCrypto.beryl_certificate_bench_verify_cert(context) == 1
      LibCrypto.beryl_certificate_bench_store_ctx_free(context)
      nil
    end
    libcrypto_arm.call
    beryl_arm = -> do
      verification.verify(leaf, intermediates, identity: identity, time: entry.timestamp)
      nil
    end
    names = ([leaf] + intermediates).map { |certificate| certificate.signature_algorithm.scheme.to_s + "/" + certificate.signature_algorithm.hash_function.to_s }
    measure(io, settings, "X.509", "verify chain: #{label} (#{intermediates.size + 1} certificates; signatures #{names.join(", ")})", beryl_arm, libcrypto_arm)
  end

  def self.run(io : IO) : Nil
    settings = Settings.from_environment
    list_of_entries = CertificateCorpus.read
    list_of_certificates = CertificateCorpus.distinct_certificates(list_of_entries)
    store = LibCrypto.beryl_certificate_bench_store_new
    Beryl::Encoding::PEM.decode(Beryl::Certificates::TrustStore::MOZILLA_ROOTS_PEM, label: "CERTIFICATE").each do |der|
      LibCrypto.beryl_certificate_bench_store_add_cert(store, openssl_certificate(der))
    end

    io.puts "Beryl #{Beryl::VERSION} against #{String.new(LibCrypto.beryl_certificate_bench_openssl_version(0))}"
    io.puts "#{settings.round_count} rounds, #{settings.seconds_per_arm} s of processor time per arm in each, the arms taking turns of about #{(SECONDS_PER_TURN * 1000).round.to_i} ms"
    io.puts
    io.puts "| Kind | Operation | Beryl operations/s (median) | libcrypto operations/s (median) | Beryl against libcrypto (median of rounds) | Paired 95% interval | At least as fast |"
    io.puts "|---|---|---|---|---|---|---|"
    measure_parse(io, settings, list_of_certificates)
    {"ECDSA leaf" => Beryl::Certificates::SignatureAlgorithm::Scheme::Ecdsa, "RSA leaf" => Beryl::Certificates::SignatureAlgorithm::Scheme::RsaPkcs1}.each do |label, scheme|
      entry = list_of_entries.find do |candidate|
        next false unless candidate.entry_type == 0
        begin
          leaf = Beryl::Certificates::Certificate.new(candidate.list_of_certificates.first)
          host = leaf.list_of_dns_names.find { |name| !name.starts_with?("*") }
          next false unless host && leaf.signature_algorithm.scheme == scheme
          intermediates = candidate.list_of_certificates[1..].map { |der| Beryl::Certificates::Certificate.new(der) }
          Beryl::Certificates::ChainVerification.new(Beryl::Certificates::TrustStore.mozilla)
            .verify(leaf, intermediates, identity: Beryl::Certificates::ServiceIdentity.new(host), time: candidate.timestamp)
          true
        rescue Beryl::Error
          false
        end
      end
      measure_verify(io, settings, label, entry, store) if entry
    end
  end
end

CertificatesAgainstLibcrypto.run(STDOUT)
