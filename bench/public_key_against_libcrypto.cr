# Speed of Beryl's curve operations next to libcrypto's.
#
#     crystal-alpha build --release bench/public_key_against_libcrypto.cr -o public_key_against_libcrypto
#     ./public_key_against_libcrypto
#
# Method (plans/BERYL_TLS_CRYPTO.md section 3.1), the same as the hash and
# cipher benchmarks: both arms live in one binary and work on the same keys
# and the same 64-byte message. A row is ten rounds, and in a round each arm
# runs for at least two seconds of processor time (time spent waiting for a
# processor is not counted). Within a round the arms take turns of about
# five milliseconds, and the arm that goes first changes every turn, so both
# see the same machine load. Each round gives one ratio, Beryl's operations
# per second divided by libcrypto's. The table reports the median of those
# ratios and their paired 95% interval (Student's t on the logarithms of the
# ratios). Beryl is "at least as fast" when the whole interval is at or
# above 1.
#
# Rows:
# - "key generation" draws a new key pair from the system's random source
#   (`Random::Secure` against `EVP_PKEY_generate`).
# - "sign" hashes the message and signs it: Ed25519, or ECDSA with SHA-256
#   and Beryl's RFC 6979 nonce against libcrypto's own nonce.
# - "verify" checks a valid signature on a key decoded once beforehand.
# - "shared secret" is the key agreement with a peer key decoded once
#   beforehand; libcrypto keeps its context and peer between operations.
#
# BERYL_BENCH_ALGORITHMS picks rows by algorithm name, separated by commas
# (for example "X25519,P-256 ECDSA"); BERYL_BENCH_SECONDS_PER_ARM and
# BERYL_BENCH_ROUNDS shorten a trial run.
require "openssl"
require "../src/beryl"

lib LibCrypto
  fun beryl_key_bench_openssl_version = OpenSSL_version(kind : LibC::Int) : LibC::Char*
  fun beryl_key_bench_evp_pkey_new_raw_private_key = EVP_PKEY_new_raw_private_key(type : LibC::Int, engine : Void*, key : UInt8*, key_bytesize : LibC::SizeT) : Void*
  fun beryl_key_bench_evp_pkey_free = EVP_PKEY_free(key : Void*)
  fun beryl_key_bench_evp_pkey_ctx_new = EVP_PKEY_CTX_new(key : Void*, engine : Void*) : Void*
  fun beryl_key_bench_evp_pkey_ctx_new_from_name = EVP_PKEY_CTX_new_from_name(library_context : Void*, name : LibC::Char*, properties : LibC::Char*) : Void*
  fun beryl_key_bench_evp_pkey_ctx_free = EVP_PKEY_CTX_free(context : Void*)
  fun beryl_key_bench_evp_pkey_derive_init = EVP_PKEY_derive_init(context : Void*) : LibC::Int
  fun beryl_key_bench_evp_pkey_derive_set_peer_ex = EVP_PKEY_derive_set_peer_ex(context : Void*, peer : Void*, validate_peer : LibC::Int) : LibC::Int
  fun beryl_key_bench_evp_pkey_derive = EVP_PKEY_derive(context : Void*, key : UInt8*, bytesize : LibC::SizeT*) : LibC::Int
  fun beryl_key_bench_evp_pkey_keygen_init = EVP_PKEY_keygen_init(context : Void*) : LibC::Int
  fun beryl_key_bench_evp_pkey_ctx_set_group_name = EVP_PKEY_CTX_set_group_name(context : Void*, name : LibC::Char*) : LibC::Int
  fun beryl_key_bench_evp_pkey_generate = EVP_PKEY_generate(context : Void*, key : Void**) : LibC::Int
  fun beryl_key_bench_evp_pkey_get_bn_param = EVP_PKEY_get_bn_param(key : Void*, name : LibC::Char*, number : Void**) : LibC::Int
  fun beryl_key_bench_evp_pkey_get_octet_string_param = EVP_PKEY_get_octet_string_param(key : Void*, name : LibC::Char*, buffer : UInt8*, capacity : LibC::SizeT, bytesize : LibC::SizeT*) : LibC::Int
  fun beryl_key_bench_bn_bn2binpad = BN_bn2binpad(number : Void*, output : UInt8*, bytesize : LibC::Int) : LibC::Int
  fun beryl_key_bench_bn_free = BN_free(number : Void*)
  fun beryl_key_bench_digest_sign_init = EVP_DigestSignInit(context : EVP_MD_CTX, key_context : Void**, digest : Void*, engine : Void*, key : Void*) : LibC::Int
  fun beryl_key_bench_digest_sign = EVP_DigestSign(context : EVP_MD_CTX, signature : UInt8*, bytesize : LibC::SizeT*, message : UInt8*, message_bytesize : LibC::SizeT) : LibC::Int
  fun beryl_key_bench_digest_verify_init = EVP_DigestVerifyInit(context : EVP_MD_CTX, key_context : Void**, digest : Void*, engine : Void*, key : Void*) : LibC::Int
  fun beryl_key_bench_digest_verify = EVP_DigestVerify(context : EVP_MD_CTX, signature : UInt8*, bytesize : LibC::SizeT, message : UInt8*, message_bytesize : LibC::SizeT) : LibC::Int
end

module PublicKeyAgainstLibcrypto
  MESSAGE_BYTESIZE =    64
  NID_X25519       =  1034
  NID_ED25519      =  1087
  SECONDS_PER_TURN = 0.005

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

  def self.check(result : LibC::Int, what : String) : Nil
    raise "libcrypto failed: #{what}" unless result == 1
  end

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

  # States a ratio of Beryl's speed to libcrypto's the way Seth reads it.
  def self.describe_ratio(ratio : Float64) : String
    factor = ratio >= 1.0 ? ratio : 1.0 / ratio
    rounded = factor < 1.1 ? factor.round(3) : factor.round(2)
    ratio >= 1.0 ? "#{rounded}× as fast" : "#{rounded}× slower"
  end

  # Runs the rounds for one row and prints it.
  def self.measure(io : IO, settings : Settings, algorithm : String, operation : String,
                   beryl_arm : Proc(Nil), libcrypto_arm : Proc(Nil)) : Nil
    return unless settings.includes_algorithm?(algorithm)

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

  # libcrypto's key generation on an algorithm (X25519, ED25519) or an EC group.
  def self.libcrypto_generate(algorithm : String, group : String? = nil) : Void*
    context = LibCrypto.beryl_key_bench_evp_pkey_ctx_new_from_name(nil, algorithm, nil)
    begin
      check LibCrypto.beryl_key_bench_evp_pkey_keygen_init(context), "keygen_init"
      check LibCrypto.beryl_key_bench_evp_pkey_ctx_set_group_name(context, group), "set_group_name" if group
      key = Pointer(Void).null
      check LibCrypto.beryl_key_bench_evp_pkey_generate(context, pointerof(key)), "generate"
      key
    ensure
      LibCrypto.beryl_key_bench_evp_pkey_ctx_free(context)
    end
  end

  def self.libcrypto_private_scalar(key : Void*, bytesize : Int32) : Bytes
    number = Pointer(Void).null
    check LibCrypto.beryl_key_bench_evp_pkey_get_bn_param(key, "priv", pointerof(number)), "get priv"
    scalar = Bytes.new(bytesize)
    LibCrypto.beryl_key_bench_bn_bn2binpad(number, scalar, bytesize)
    LibCrypto.beryl_key_bench_bn_free(number)
    scalar
  end

  def self.libcrypto_public_point(key : Void*) : Bytes
    point = Bytes.new(200)
    bytesize = LibC::SizeT.new(0)
    check LibCrypto.beryl_key_bench_evp_pkey_get_octet_string_param(key, "encoded-pub-key", point, point.size, pointerof(bytesize)), "get pub"
    point[0, bytesize].dup
  end

  def self.libcrypto_sign(context : LibCrypto::EVP_MD_CTX, key : Void*, digest : Void*, message : Bytes, signature : Bytes) : Bytes
    check LibCrypto.beryl_key_bench_digest_sign_init(context, nil, digest, nil, key), "DigestSignInit"
    bytesize = LibC::SizeT.new(signature.size)
    check LibCrypto.beryl_key_bench_digest_sign(context, signature, pointerof(bytesize), message, message.size), "DigestSign"
    signature[0, bytesize]
  end

  def self.libcrypto_verify(context : LibCrypto::EVP_MD_CTX, key : Void*, digest : Void*, message : Bytes, signature : Bytes) : Bool
    check LibCrypto.beryl_key_bench_digest_verify_init(context, nil, digest, nil, key), "DigestVerifyInit"
    LibCrypto.beryl_key_bench_digest_verify(context, signature, signature.size, message, message.size) == 1
  end

  # A derivation context on *key* with *peer* set once.
  def self.libcrypto_derivation(key : Void*, peer : Void*) : Void*
    context = LibCrypto.beryl_key_bench_evp_pkey_ctx_new(key, nil)
    check LibCrypto.beryl_key_bench_evp_pkey_derive_init(context), "derive_init"
    check LibCrypto.beryl_key_bench_evp_pkey_derive_set_peer_ex(context, peer, 1), "set_peer"
    context
  end

  def self.libcrypto_derive(context : Void*, shared : Bytes) : Bytes
    bytesize = LibC::SizeT.new(shared.size)
    check LibCrypto.beryl_key_bench_evp_pkey_derive(context, shared, pointerof(bytesize)), "derive"
    shared[0, bytesize]
  end

  def self.measure_x25519(io : IO, settings : Settings) : Nil
    own_key = libcrypto_generate("X25519")
    peer_key = libcrypto_generate("X25519")
    beryl_own = Beryl::Crypto::V1::X25519::PrivateKey.generate
    beryl_peer = Beryl::Crypto::V1::X25519::PrivateKey.generate
    derivation = libcrypto_derivation(own_key, peer_key)
    shared = Bytes.new(32)

    beryl_peer_public_key = beryl_peer.public_key
    beryl_shared = beryl_own.shared_secret(beryl_peer_public_key)
    raise "Beryl's X25519 sides disagree" unless beryl_shared && beryl_shared == beryl_peer.shared_secret(beryl_own.public_key)

    measure(io, settings, "X25519", "key generation",
      -> { Beryl::Crypto::V1::X25519::PrivateKey.generate.public_key; nil },
      -> { LibCrypto.beryl_key_bench_evp_pkey_free(libcrypto_generate("X25519")); nil })
    measure(io, settings, "X25519", "shared secret",
      -> { beryl_own.shared_secret(beryl_peer_public_key); nil },
      -> { libcrypto_derive(derivation, shared); nil })
    LibCrypto.beryl_key_bench_evp_pkey_ctx_free(derivation)
  end

  def self.measure_ed25519(io : IO, settings : Settings) : Nil
    seed = Random::Secure.random_bytes(32)
    beryl_key = Beryl::Crypto::V1::Ed25519::SigningKey.new(seed)
    libcrypto_key = LibCrypto.beryl_key_bench_evp_pkey_new_raw_private_key(NID_ED25519, nil, seed, seed.size)
    message = Random::Secure.random_bytes(MESSAGE_BYTESIZE)
    context = LibCrypto.evp_md_ctx_new
    signature_buffer = Bytes.new(64)

    beryl_signature = beryl_key.sign(message)
    libcrypto_signature = libcrypto_sign(context, libcrypto_key, Pointer(Void).null, message, signature_buffer).dup
    raise "the two arms disagree on Ed25519" unless beryl_signature == libcrypto_signature
    raise "libcrypto refuses Beryl's Ed25519 signature" unless libcrypto_verify(context, libcrypto_key, Pointer(Void).null, message, beryl_signature)

    verification_key = beryl_key.verification_key
    measure(io, settings, "Ed25519", "key generation",
      -> { Beryl::Crypto::V1::Ed25519::SigningKey.generate; nil },
      -> { LibCrypto.beryl_key_bench_evp_pkey_free(libcrypto_generate("ED25519")); nil })
    measure(io, settings, "Ed25519", "sign",
      -> { beryl_key.sign(message); nil },
      -> { libcrypto_sign(context, libcrypto_key, Pointer(Void).null, message, signature_buffer); nil })
    measure(io, settings, "Ed25519", "verify",
      -> { raise "Beryl refused a valid signature" unless verification_key.verify(message, beryl_signature); nil },
      -> { raise "libcrypto refused a valid signature" unless libcrypto_verify(context, libcrypto_key, Pointer(Void).null, message, beryl_signature); nil })
    LibCrypto.evp_md_ctx_free(context)
    LibCrypto.beryl_key_bench_evp_pkey_free(libcrypto_key)
  end

  def self.measure_p256(io : IO, settings : Settings) : Nil
    group = "P-256"
    libcrypto_key = libcrypto_generate("EC", group)
    libcrypto_peer = libcrypto_generate("EC", group)
    beryl_key = Beryl::Crypto::V1::P256::PrivateKey.new(libcrypto_private_scalar(libcrypto_key, 32))
    beryl_peer = Beryl::Crypto::V1::P256::PublicKey.new(libcrypto_public_point(libcrypto_peer))
    raise "the two arms hold different P-256 keys" unless beryl_key.public_key.to_uncompressed == libcrypto_public_point(libcrypto_key)

    message = Random::Secure.random_bytes(MESSAGE_BYTESIZE)
    sha256 = LibCrypto.evp_get_digestbyname("SHA256").as(Void*)
    context = LibCrypto.evp_md_ctx_new
    signature_buffer = Bytes.new(80)
    derivation = libcrypto_derivation(libcrypto_key, libcrypto_peer)
    shared = Bytes.new(32)

    beryl_signature = beryl_key.sign(message)
    libcrypto_signature = libcrypto_sign(context, libcrypto_key, sha256, message, signature_buffer).dup
    raise "libcrypto refuses Beryl's P-256 signature" unless libcrypto_verify(context, libcrypto_key, sha256, message, beryl_signature)
    raise "Beryl refuses libcrypto's P-256 signature" unless beryl_key.public_key.verify(message, libcrypto_signature)
    raise "the two arms disagree on P-256 ECDH" unless beryl_key.shared_secret(beryl_peer) == libcrypto_derive(derivation, shared)

    public_key = beryl_key.public_key
    measure(io, settings, "P-256", "key generation",
      -> { Beryl::Crypto::V1::P256::PrivateKey.generate; nil },
      -> { LibCrypto.beryl_key_bench_evp_pkey_free(libcrypto_generate("EC", group)); nil })
    measure(io, settings, "P-256 ECDSA", "sign",
      -> { beryl_key.sign(message); nil },
      -> { libcrypto_sign(context, libcrypto_key, sha256, message, signature_buffer); nil })
    measure(io, settings, "P-256 ECDSA", "verify",
      -> { raise "Beryl refused a valid signature" unless public_key.verify(message, libcrypto_signature); nil },
      -> { raise "libcrypto refused a valid signature" unless libcrypto_verify(context, libcrypto_key, sha256, message, libcrypto_signature); nil })
    measure(io, settings, "P-256 ECDH", "shared secret",
      -> { beryl_key.shared_secret(beryl_peer); nil },
      -> { libcrypto_derive(derivation, shared); nil })
    LibCrypto.beryl_key_bench_evp_pkey_ctx_free(derivation)
    LibCrypto.evp_md_ctx_free(context)
  end

  def self.measure_p384(io : IO, settings : Settings) : Nil
    libcrypto_key = libcrypto_generate("EC", "P-384")
    public_key = Beryl::Crypto::V1::P384::PublicKey.new(libcrypto_public_point(libcrypto_key))
    message = Random::Secure.random_bytes(MESSAGE_BYTESIZE)
    sha384 = LibCrypto.evp_get_digestbyname("SHA384").as(Void*)
    context = LibCrypto.evp_md_ctx_new
    signature = libcrypto_sign(context, libcrypto_key, sha384, message, Bytes.new(120)).dup
    raise "Beryl refuses libcrypto's P-384 signature" unless public_key.verify(message, signature)

    measure(io, settings, "P-384 ECDSA", "verify",
      -> { raise "Beryl refused a valid signature" unless public_key.verify(message, signature); nil },
      -> { raise "libcrypto refused a valid signature" unless libcrypto_verify(context, libcrypto_key, sha384, message, signature); nil })
    LibCrypto.evp_md_ctx_free(context)
  end

  def self.run(io : IO) : Nil
    settings = Settings.from_environment
    io.puts "Beryl #{Beryl::VERSION} against #{String.new(LibCrypto.beryl_key_bench_openssl_version(0))}"
    io.puts "#{settings.round_count} rounds, #{settings.seconds_per_arm} s of processor time per arm in each, the arms taking turns of about #{(SECONDS_PER_TURN * 1000).round.to_i} ms"
    io.puts "Data Independent Timing in use by Beryl: #{Beryl::Crypto::ProcessorFeatures::HAS_DATA_INDEPENDENT_TIMING}"
    io.puts
    io.puts "| Algorithm | Operation | Beryl operations/s (median) | libcrypto operations/s (median) | Beryl against libcrypto (median of rounds) | Paired 95% interval | At least as fast |"
    io.puts "|---|---|---|---|---|---|---|"
    measure_x25519(io, settings)
    measure_ed25519(io, settings)
    measure_p256(io, settings)
    measure_p384(io, settings)
  end
end

PublicKeyAgainstLibcrypto.run(STDOUT)
