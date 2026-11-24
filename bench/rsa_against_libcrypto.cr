# Speed of Beryl's RSA next to libcrypto's.
#
#     crystal-alpha build --release bench/rsa_against_libcrypto.cr -o rsa_against_libcrypto
#     ./rsa_against_libcrypto
#
# Method (plans/BERYL_TLS_CRYPTO.md section 3.1), the same as
# bench/ciphers_against_libcrypto.cr: both arms live in one binary and use the
# same key, made by libcrypto, on the same 32-byte message. A row is ten
# rounds, and in a round each arm runs for at least two seconds of processor
# time (time spent waiting for a processor is not counted). Within a round
# the arms take turns of about 5 milliseconds, and the arm that goes first
# changes every turn, so both see the same machine load. Each round gives one
# ratio, Beryl's operations per second divided by libcrypto's; the table
# reports the median of those ratios and their paired 95% interval (Student's
# t on the logarithms of the ratios). Beryl is "at least as fast" when the
# whole interval is at or above 1.
#
# Rows, at 2,048, 3,072 and 4,096 bits, all with SHA-256 (and MGF1-SHA-256):
# PKCS #1 v1.5 sign and verify, PSS sign (salt of 32 bytes) and verify, OAEP
# encrypt and decrypt. Each arm hashes the message itself. The public
# exponent is 65,537.
#
# BERYL_BENCH_ALGORITHMS picks rows by operation name, separated by commas
# (for example "PSS sign,OAEP decrypt"); BERYL_BENCH_SIZES picks key sizes in
# bits; BERYL_BENCH_SECONDS_PER_ARM and BERYL_BENCH_ROUNDS shorten a trial run.
require "openssl"
require "../src/beryl"

lib LibCrypto
  fun beryl_rsa_bench_openssl_version = OpenSSL_version(kind : LibC::Int) : LibC::Char*
  fun beryl_rsa_bench_evp_pkey_ctx_new_from_name = EVP_PKEY_CTX_new_from_name(libctx : Void*, name : LibC::Char*, propquery : LibC::Char*) : Void*
  fun beryl_rsa_bench_evp_pkey_ctx_new = EVP_PKEY_CTX_new(pkey : Void*, engine : Void*) : Void*
  fun beryl_rsa_bench_evp_pkey_ctx_free = EVP_PKEY_CTX_free(ctx : Void*)
  fun beryl_rsa_bench_evp_pkey_keygen_init = EVP_PKEY_keygen_init(ctx : Void*) : LibC::Int
  fun beryl_rsa_bench_evp_pkey_generate = EVP_PKEY_generate(ctx : Void*, pkey : Void**) : LibC::Int
  fun beryl_rsa_bench_set_rsa_keygen_bits = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx : Void*, bits : LibC::Int) : LibC::Int
  fun beryl_rsa_bench_evp_pkey_get_bn_param = EVP_PKEY_get_bn_param(pkey : Void*, key_name : LibC::Char*, bn : Void**) : LibC::Int
  fun beryl_rsa_bench_bn_num_bits = BN_num_bits(bn : Void*) : LibC::Int
  fun beryl_rsa_bench_bn_bn2binpad = BN_bn2binpad(bn : Void*, to : UInt8*, tolen : LibC::Int) : LibC::Int
  fun beryl_rsa_bench_bn_free = BN_free(bn : Void*)
  fun beryl_rsa_bench_evp_pkey_sign_init = EVP_PKEY_sign_init(ctx : Void*) : LibC::Int
  fun beryl_rsa_bench_evp_pkey_sign = EVP_PKEY_sign(ctx : Void*, sig : UInt8*, siglen : LibC::SizeT*, tbs : UInt8*, tbslen : LibC::SizeT) : LibC::Int
  fun beryl_rsa_bench_evp_pkey_verify_init = EVP_PKEY_verify_init(ctx : Void*) : LibC::Int
  fun beryl_rsa_bench_evp_pkey_verify = EVP_PKEY_verify(ctx : Void*, sig : UInt8*, siglen : LibC::SizeT, tbs : UInt8*, tbslen : LibC::SizeT) : LibC::Int
  fun beryl_rsa_bench_evp_pkey_encrypt_init = EVP_PKEY_encrypt_init(ctx : Void*) : LibC::Int
  fun beryl_rsa_bench_evp_pkey_encrypt = EVP_PKEY_encrypt(ctx : Void*, out : UInt8*, outlen : LibC::SizeT*, input : UInt8*, inlen : LibC::SizeT) : LibC::Int
  fun beryl_rsa_bench_evp_pkey_decrypt_init = EVP_PKEY_decrypt_init(ctx : Void*) : LibC::Int
  fun beryl_rsa_bench_evp_pkey_decrypt = EVP_PKEY_decrypt(ctx : Void*, out : UInt8*, outlen : LibC::SizeT*, input : UInt8*, inlen : LibC::SizeT) : LibC::Int
  fun beryl_rsa_bench_set_rsa_padding = EVP_PKEY_CTX_set_rsa_padding(ctx : Void*, padding : LibC::Int) : LibC::Int
  fun beryl_rsa_bench_set_signature_md = EVP_PKEY_CTX_set_signature_md(ctx : Void*, md : EVP_MD) : LibC::Int
  fun beryl_rsa_bench_set_rsa_pss_saltlen = EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx : Void*, saltlen : LibC::Int) : LibC::Int
  fun beryl_rsa_bench_set_rsa_mgf1_md = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx : Void*, md : EVP_MD) : LibC::Int
  fun beryl_rsa_bench_set_rsa_oaep_md = EVP_PKEY_CTX_set_rsa_oaep_md(ctx : Void*, md : EVP_MD) : LibC::Int
end

module RsaAgainstLibcrypto
  alias RSA = Beryl::Crypto::V1::RSA
  alias SHA256 = Beryl::Crypto::V1::SHA256

  LIST_OF_KEY_BIT_COUNTS = [2_048, 3_072, 4_096]
  MESSAGE_BYTESIZE       =    32
  SALT_BYTESIZE          =    32
  SECONDS_PER_TURN       = 0.005

  RSA_PKCS1_PADDING      = 1
  RSA_PKCS1_OAEP_PADDING = 4
  RSA_PKCS1_PSS_PADDING  = 6

  # Two-sided 95% points of Student's t distribution, by degrees of freedom.
  STUDENT_T_95_PERCENT = [12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
                          2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086]

  # `CLOCK_THREAD_CPUTIME_ID` of <time.h>.
  THREAD_PROCESSOR_TIME_CLOCK = {% if flag?(:darwin) %} 16 {% else %} 3 {% end %}

  record Settings, seconds_per_arm : Float64, round_count : Int32, list_of_algorithms : Array(String)?,
    list_of_key_bit_counts : Array(Int32) do
    def self.from_environment : Settings
      new(
        ENV["BERYL_BENCH_SECONDS_PER_ARM"]?.try(&.to_f) || 2.0,
        ENV["BERYL_BENCH_ROUNDS"]?.try(&.to_i) || 10,
        ENV["BERYL_BENCH_ALGORITHMS"]?.try(&.split(',').map(&.strip)),
        ENV["BERYL_BENCH_SIZES"]?.try(&.split(',').map(&.strip.to_i)) || LIST_OF_KEY_BIT_COUNTS,
      )
    end

    def includes_algorithm?(algorithm : String) : Bool
      selected = list_of_algorithms
      selected.nil? || selected.includes?(algorithm)
    end
  end

  # One libcrypto key and the contexts each operation reuses.
  class LibcryptoKey
    getter key : Void*

    def initialize(bit_count : Int32)
      context = LibCrypto.beryl_rsa_bench_evp_pkey_ctx_new_from_name(Pointer(Void).null, "RSA", Pointer(UInt8).null)
      @key = Pointer(Void).null
      check LibCrypto.beryl_rsa_bench_evp_pkey_keygen_init(context)
      check LibCrypto.beryl_rsa_bench_set_rsa_keygen_bits(context, bit_count)
      check LibCrypto.beryl_rsa_bench_evp_pkey_generate(context, pointerof(@key))
      LibCrypto.beryl_rsa_bench_evp_pkey_ctx_free(context)
    end

    def component(parameter_name : String) : Bytes
      big_number = Pointer(Void).null
      check LibCrypto.beryl_rsa_bench_evp_pkey_get_bn_param(@key, parameter_name, pointerof(big_number))
      bytes = Bytes.new((LibCrypto.beryl_rsa_bench_bn_num_bits(big_number) + 7) // 8)
      LibCrypto.beryl_rsa_bench_bn_bn2binpad(big_number, bytes, bytes.size)
      LibCrypto.beryl_rsa_bench_bn_free(big_number)
      bytes
    end

    def beryl_private_key : RSA::PrivateKey
      RSA::PrivateKey.new(
        modulus: component("n"), public_exponent: component("e"), private_exponent: component("d"),
        first_prime: component("rsa-factor1"), second_prime: component("rsa-factor2"),
        first_prime_exponent: component("rsa-exponent1"), second_prime_exponent: component("rsa-exponent2"),
        coefficient: component("rsa-coefficient1"),
      )
    end

    # A context set up for one operation, kept for the whole row.
    def context_for(operation : Symbol, padding : Int32) : Void*
      context = LibCrypto.beryl_rsa_bench_evp_pkey_ctx_new(@key, Pointer(Void).null)
      evp_md = LibCrypto.evp_get_digestbyname("SHA256")
      case operation
      when :sign    then check LibCrypto.beryl_rsa_bench_evp_pkey_sign_init(context)
      when :verify  then check LibCrypto.beryl_rsa_bench_evp_pkey_verify_init(context)
      when :encrypt then check LibCrypto.beryl_rsa_bench_evp_pkey_encrypt_init(context)
      else               check LibCrypto.beryl_rsa_bench_evp_pkey_decrypt_init(context)
      end
      check LibCrypto.beryl_rsa_bench_set_rsa_padding(context, padding)
      if padding == RSA_PKCS1_OAEP_PADDING
        check LibCrypto.beryl_rsa_bench_set_rsa_oaep_md(context, evp_md)
        check LibCrypto.beryl_rsa_bench_set_rsa_mgf1_md(context, evp_md)
      else
        check LibCrypto.beryl_rsa_bench_set_signature_md(context, evp_md)
      end
      if padding == RSA_PKCS1_PSS_PADDING
        check LibCrypto.beryl_rsa_bench_set_rsa_mgf1_md(context, evp_md)
        check LibCrypto.beryl_rsa_bench_set_rsa_pss_saltlen(context, SALT_BYTESIZE)
      end
      context
    end

    private def check(result : LibC::Int) : Nil
      raise "a libcrypto RSA call failed" unless result == 1
    end
  end

  def self.processor_seconds : Float64
    if LibC.clock_gettime(LibC::ClockidT.new(THREAD_PROCESSOR_TIME_CLOCK), out time) != 0
      raise RuntimeError.from_errno("clock_gettime")
    end
    time.tv_sec.to_f64 + time.tv_nsec.to_f64 / 1_000_000_000
  end

  # Returns how many calls of the slower arm fill about one turn.
  def self.operations_per_turn(beryl_arm : Proc(Nil), libcrypto_arm : Proc(Nil)) : Int32
    started_at = processor_seconds
    beryl_arm.call
    libcrypto_arm.call
    seconds_for_both = processor_seconds - started_at
    Math.max(1, (2 * SECONDS_PER_TURN / Math.max(seconds_for_both, 1e-7)).to_i)
  end

  # Runs one round and returns each arm's operations per second of processor
  # time over its own turns.
  def self.operations_per_second_of_each_arm(seconds_per_arm : Float64, operations_per_turn : Int32,
                                             beryl_arm : Proc(Nil), libcrypto_arm : Proc(Nil)) : {Float64, Float64}
    operation_count = 0_u64
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

      beryl_seconds += beryl_goes_first ? changed_at - started_at : finished_at - changed_at
      libcrypto_seconds += beryl_goes_first ? finished_at - changed_at : changed_at - started_at
      operation_count += operations_per_turn
      beryl_goes_first = !beryl_goes_first
    end
    {operation_count / beryl_seconds, operation_count / libcrypto_seconds}
  end

  def self.median(list_of_values : Array(Float64)) : Float64
    sorted = list_of_values.sort
    middle = sorted.size // 2
    sorted.size.odd? ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2
  end

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

  def self.measure(io : IO, settings : Settings, algorithm : String, bit_count : Int32,
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
    io.puts "| RSA-#{bit_count} | #{algorithm} | #{median(list_of_beryl_speeds).round(1)} | #{median(list_of_libcrypto_speeds).round(1)} | " \
            "#{describe_ratio(median(list_of_ratios))} | #{describe_ratio(interval[0])} to #{describe_ratio(interval[1])} | " \
            "#{interval[0] >= 1.0 ? "yes" : "no"} |"
    io.flush
  end

  def self.libcrypto_digest(message : Bytes) : Bytes
    OpenSSL::Digest.new("SHA256").update(message).final
  end

  # Measures every row at one key size.
  def self.measure_key_size(io : IO, settings : Settings, bit_count : Int32) : Nil
    libcrypto_key = LibcryptoKey.new(bit_count)
    private_key = libcrypto_key.beryl_private_key
    public_key = private_key.public_key
    modulus_bytesize = private_key.modulus_bytesize
    message = Random::Secure.random_bytes(MESSAGE_BYTESIZE)
    output = Bytes.new(modulus_bytesize)
    output_bytesize = LibC::SizeT.new(0)

    # Both arms must agree before either is timed.
    pkcs1_signature = private_key.sign_with_pkcs1(message, hash_function: SHA256)
    pss_signature = private_key.sign_with_pss(message, hash_function: SHA256, salt_bytesize: SALT_BYTESIZE)
    ciphertext = public_key.encrypt_with_oaep(message, hash_function: SHA256)
    pkcs1_signing_context = libcrypto_key.context_for(:sign, RSA_PKCS1_PADDING)
    pkcs1_verifying_context = libcrypto_key.context_for(:verify, RSA_PKCS1_PADDING)
    pss_signing_context = libcrypto_key.context_for(:sign, RSA_PKCS1_PSS_PADDING)
    pss_verifying_context = libcrypto_key.context_for(:verify, RSA_PKCS1_PSS_PADDING)
    digest = libcrypto_digest(message)
    {% for pair in [{"pkcs1_verifying_context", "pkcs1_signature"}, {"pss_verifying_context", "pss_signature"}] %}
      unless LibCrypto.beryl_rsa_bench_evp_pkey_verify({{ pair[0].id }}, {{ pair[1].id }}, {{ pair[1].id }}.size, digest, digest.size) == 1
        raise "libcrypto refuses Beryl's {{ pair[1].id }}"
      end
    {% end %}

    encrypting_context = libcrypto_key.context_for(:encrypt, RSA_PKCS1_OAEP_PADDING)
    decrypting_context = libcrypto_key.context_for(:decrypt, RSA_PKCS1_OAEP_PADDING)
    output_bytesize = LibC::SizeT.new(output.size)
    LibCrypto.beryl_rsa_bench_evp_pkey_decrypt(decrypting_context, output, pointerof(output_bytesize), ciphertext, ciphertext.size)
    raise "libcrypto does not decrypt Beryl's OAEP ciphertext" unless output[0, output_bytesize] == message

    measure(io, settings, "PKCS#1 v1.5 sign", bit_count,
      -> { private_key.sign_with_pkcs1(message, hash_function: SHA256); nil },
      -> {
        digest = libcrypto_digest(message)
        output_bytesize = LibC::SizeT.new(output.size)
        LibCrypto.beryl_rsa_bench_evp_pkey_sign(pkcs1_signing_context, output, pointerof(output_bytesize), digest, digest.size); nil
      })
    measure(io, settings, "PSS sign", bit_count,
      -> { private_key.sign_with_pss(message, hash_function: SHA256, salt_bytesize: SALT_BYTESIZE); nil },
      -> {
        digest = libcrypto_digest(message)
        output_bytesize = LibC::SizeT.new(output.size)
        LibCrypto.beryl_rsa_bench_evp_pkey_sign(pss_signing_context, output, pointerof(output_bytesize), digest, digest.size); nil
      })
    measure(io, settings, "PKCS#1 v1.5 verify", bit_count,
      -> { public_key.verify_pkcs1_signature(message, pkcs1_signature, hash_function: SHA256); nil },
      -> {
        digest = libcrypto_digest(message)
        LibCrypto.beryl_rsa_bench_evp_pkey_verify(pkcs1_verifying_context, pkcs1_signature, pkcs1_signature.size, digest, digest.size); nil
      })
    measure(io, settings, "PSS verify", bit_count,
      -> { public_key.verify_pss_signature(message, pss_signature, hash_function: SHA256, salt_bytesize: SALT_BYTESIZE); nil },
      -> {
        digest = libcrypto_digest(message)
        LibCrypto.beryl_rsa_bench_evp_pkey_verify(pss_verifying_context, pss_signature, pss_signature.size, digest, digest.size); nil
      })
    measure(io, settings, "OAEP encrypt", bit_count,
      -> { public_key.encrypt_with_oaep(message, hash_function: SHA256); nil },
      -> {
        output_bytesize = LibC::SizeT.new(output.size)
        LibCrypto.beryl_rsa_bench_evp_pkey_encrypt(encrypting_context, output, pointerof(output_bytesize), message, message.size); nil
      })
    measure(io, settings, "OAEP decrypt", bit_count,
      -> { private_key.decrypt_with_oaep(ciphertext, hash_function: SHA256); nil },
      -> {
        output_bytesize = LibC::SizeT.new(output.size)
        LibCrypto.beryl_rsa_bench_evp_pkey_decrypt(decrypting_context, output, pointerof(output_bytesize), ciphertext, ciphertext.size); nil
      })
  end

  def self.run(io : IO) : Nil
    settings = Settings.from_environment
    io.puts "Beryl #{Beryl::VERSION} against #{String.new(LibCrypto.beryl_rsa_bench_openssl_version(0))}"
    io.puts "#{settings.round_count} rounds, #{settings.seconds_per_arm} s of processor time per arm in each, the arms taking turns of about #{(SECONDS_PER_TURN * 1000).to_i} ms"
    io.puts
    io.puts "| Key | Operation | Beryl operations/s (median) | libcrypto operations/s (median) | Beryl against libcrypto (median of rounds) | Paired 95% interval | At least as fast |"
    io.puts "|---|---|---|---|---|---|---|"
    settings.list_of_key_bit_counts.each { |bit_count| measure_key_size(io, settings, bit_count) }
  end
end

RsaAgainstLibcrypto.run(STDOUT)
