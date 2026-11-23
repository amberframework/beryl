require "./libcrypto_differential_spec"

# Differential test of Beryl's RSA against libcrypto. libcrypto makes a pool
# of keys; Beryl builds the same keys from their components. Each case draws
# a hash, a message and (for PSS and OAEP) a salt size or a label from the
# case generator, then checks:
#
# - PKCS #1 v1.5: Beryl's signature equals libcrypto's, byte for byte, and
#   each side verifies it;
# - PSS: libcrypto verifies Beryl's signature and Beryl verifies libcrypto's;
# - OAEP: libcrypto decrypts Beryl's ciphertext and Beryl decrypts
#   libcrypto's, to the message;
# - and in every scheme, a mutated signature, message or ciphertext (one bit
#   flipped, or a value at or above the modulus) gets the same verdict from
#   both sides.
#
#     crystal-alpha spec --release --tag differential spec/differential/libcrypto_rsa_differential_spec.cr -e "RSA-2048 PKCS#1 v1.5 matches"
#
# The names are `RSA-<bits> PKCS#1 v1.5 matches`, `RSA-<bits> PSS matches`
# and `RSA-<bits> OAEP matches` for 2,048, 3,072 and 4,096 bits; run one per
# process. Cases: 20,000, 5,000 and 2,000 per scheme at the three sizes
# unless BERYL_DIFFERENTIAL_CASE_COUNT says otherwise. The seed and first
# case come from the environment variables the hash differential documents.
# The keys come from libcrypto's generator, not from the seed; a mismatch
# prints the key's components so the case can be replayed by hand.
lib LibCrypto
  fun beryl_rsa_spec_evp_pkey_ctx_new_from_name = EVP_PKEY_CTX_new_from_name(libctx : Void*, name : LibC::Char*, propquery : LibC::Char*) : Void*
  fun beryl_rsa_spec_evp_pkey_ctx_new = EVP_PKEY_CTX_new(pkey : Void*, engine : Void*) : Void*
  fun beryl_rsa_spec_evp_pkey_ctx_free = EVP_PKEY_CTX_free(ctx : Void*)
  fun beryl_rsa_spec_evp_pkey_free = EVP_PKEY_free(pkey : Void*)
  fun beryl_rsa_spec_evp_pkey_keygen_init = EVP_PKEY_keygen_init(ctx : Void*) : LibC::Int
  fun beryl_rsa_spec_evp_pkey_generate = EVP_PKEY_generate(ctx : Void*, pkey : Void**) : LibC::Int
  fun beryl_rsa_spec_set_rsa_keygen_bits = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx : Void*, bits : LibC::Int) : LibC::Int
  fun beryl_rsa_spec_evp_pkey_get_bn_param = EVP_PKEY_get_bn_param(pkey : Void*, key_name : LibC::Char*, bn : Void**) : LibC::Int
  fun beryl_rsa_spec_bn_num_bits = BN_num_bits(bn : Void*) : LibC::Int
  fun beryl_rsa_spec_bn_bn2binpad = BN_bn2binpad(bn : Void*, to : UInt8*, tolen : LibC::Int) : LibC::Int
  fun beryl_rsa_spec_bn_free = BN_free(bn : Void*)
  fun beryl_rsa_spec_evp_pkey_sign_init = EVP_PKEY_sign_init(ctx : Void*) : LibC::Int
  fun beryl_rsa_spec_evp_pkey_sign = EVP_PKEY_sign(ctx : Void*, sig : UInt8*, siglen : LibC::SizeT*, tbs : UInt8*, tbslen : LibC::SizeT) : LibC::Int
  fun beryl_rsa_spec_evp_pkey_verify_init = EVP_PKEY_verify_init(ctx : Void*) : LibC::Int
  fun beryl_rsa_spec_evp_pkey_verify = EVP_PKEY_verify(ctx : Void*, sig : UInt8*, siglen : LibC::SizeT, tbs : UInt8*, tbslen : LibC::SizeT) : LibC::Int
  fun beryl_rsa_spec_evp_pkey_encrypt_init = EVP_PKEY_encrypt_init(ctx : Void*) : LibC::Int
  fun beryl_rsa_spec_evp_pkey_encrypt = EVP_PKEY_encrypt(ctx : Void*, out : UInt8*, outlen : LibC::SizeT*, input : UInt8*, inlen : LibC::SizeT) : LibC::Int
  fun beryl_rsa_spec_evp_pkey_decrypt_init = EVP_PKEY_decrypt_init(ctx : Void*) : LibC::Int
  fun beryl_rsa_spec_evp_pkey_decrypt = EVP_PKEY_decrypt(ctx : Void*, out : UInt8*, outlen : LibC::SizeT*, input : UInt8*, inlen : LibC::SizeT) : LibC::Int
  fun beryl_rsa_spec_set_rsa_padding = EVP_PKEY_CTX_set_rsa_padding(ctx : Void*, padding : LibC::Int) : LibC::Int
  fun beryl_rsa_spec_set_signature_md = EVP_PKEY_CTX_set_signature_md(ctx : Void*, md : EVP_MD) : LibC::Int
  fun beryl_rsa_spec_set_rsa_pss_saltlen = EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx : Void*, saltlen : LibC::Int) : LibC::Int
  fun beryl_rsa_spec_set_rsa_mgf1_md = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx : Void*, md : EVP_MD) : LibC::Int
  fun beryl_rsa_spec_set_rsa_oaep_md = EVP_PKEY_CTX_set_rsa_oaep_md(ctx : Void*, md : EVP_MD) : LibC::Int
  fun beryl_rsa_spec_set0_rsa_oaep_label = EVP_PKEY_CTX_set0_rsa_oaep_label(ctx : Void*, label : Void*, llen : LibC::Int) : LibC::Int
  fun beryl_rsa_spec_crypto_malloc = CRYPTO_malloc(num : LibC::SizeT, file : LibC::Char*, line : LibC::Int) : Void*
end

module LibcryptoRsaDifferential
  alias RSA = Beryl::Crypto::V1::RSA

  RSA_PKCS1_PADDING      = 1
  RSA_PKCS1_OAEP_PADDING = 4
  RSA_PKCS1_PSS_PADDING  = 6

  DEFAULT_CASE_COUNT_BY_BIT_COUNT = {2_048 => 20_000, 3_072 => 5_000, 4_096 => 2_000}
  KEY_POOL_SIZE_BY_BIT_COUNT      = {2_048 => 8, 3_072 => 4, 4_096 => 2}
  LARGEST_MESSAGE_BYTESIZE        = 1_024
  LARGEST_LABEL_BYTESIZE          =    32

  # The hashes, by libcrypto name, and whether each scheme takes them.
  LIST_OF_SIGNING_HASH_NAMES = ["SHA224", "SHA256", "SHA384", "SHA512", "SHA512-256"]
  LIST_OF_OAEP_HASH_NAMES    = ["SHA1"] + LIST_OF_SIGNING_HASH_NAMES

  # A key made by libcrypto, with Beryl's copy built from its components.
  class KeyPair
    getter libcrypto_key : Void*
    getter beryl_key : RSA::PrivateKey
    getter list_of_components : Array(String)

    def initialize(@libcrypto_key : Void*, @beryl_key : RSA::PrivateKey, @list_of_components : Array(String))
    end

    def describe : String
      "key n=#{list_of_components[0]} e=#{list_of_components[1]} d=#{list_of_components[2]} p=#{list_of_components[3]} q=#{list_of_components[4]}"
    end
  end

  def self.case_count_for(bit_count : Int32) : Int32
    ENV["BERYL_DIFFERENTIAL_CASE_COUNT"]?.try(&.to_i) || DEFAULT_CASE_COUNT_BY_BIT_COUNT[bit_count]
  end

  def self.generate_key_pair(bit_count : Int32) : KeyPair
    context = LibCrypto.beryl_rsa_spec_evp_pkey_ctx_new_from_name(Pointer(Void).null, "RSA", Pointer(UInt8).null)
    raise "libcrypto could not make an RSA key context" if context.null?
    libcrypto_key = Pointer(Void).null
    begin
      check LibCrypto.beryl_rsa_spec_evp_pkey_keygen_init(context)
      check LibCrypto.beryl_rsa_spec_set_rsa_keygen_bits(context, bit_count)
      check LibCrypto.beryl_rsa_spec_evp_pkey_generate(context, pointerof(libcrypto_key))
    ensure
      LibCrypto.beryl_rsa_spec_evp_pkey_ctx_free(context)
    end

    list_of_components = ["n", "e", "d", "rsa-factor1", "rsa-factor2", "rsa-exponent1", "rsa-exponent2", "rsa-coefficient1"].map do |parameter_name|
      component_bytes(libcrypto_key, parameter_name)
    end
    beryl_key = RSA::PrivateKey.new(
      modulus: list_of_components[0], public_exponent: list_of_components[1], private_exponent: list_of_components[2],
      first_prime: list_of_components[3], second_prime: list_of_components[4], first_prime_exponent: list_of_components[5],
      second_prime_exponent: list_of_components[6], coefficient: list_of_components[7],
    )
    KeyPair.new(libcrypto_key, beryl_key, list_of_components.map(&.hexstring))
  end

  def self.component_bytes(libcrypto_key : Void*, parameter_name : String) : Bytes
    big_number = Pointer(Void).null
    check LibCrypto.beryl_rsa_spec_evp_pkey_get_bn_param(libcrypto_key, parameter_name, pointerof(big_number))
    bytes = Bytes.new((LibCrypto.beryl_rsa_spec_bn_num_bits(big_number) + 7) // 8)
    LibCrypto.beryl_rsa_spec_bn_bn2binpad(big_number, bytes, bytes.size)
    LibCrypto.beryl_rsa_spec_bn_free(big_number)
    bytes
  end

  def self.check(result : LibC::Int) : Nil
    raise "a libcrypto RSA call failed" unless result == 1
  end

  # Runs *operation* (sign, verify, encrypt or decrypt) on a fresh context of
  # *libcrypto_key* after the block has set its parameters.
  def self.with_context(libcrypto_key : Void*, & : Void* -> T) : T forall T
    context = LibCrypto.beryl_rsa_spec_evp_pkey_ctx_new(libcrypto_key, Pointer(Void).null)
    raise "libcrypto could not make a key context" if context.null?
    begin
      yield context
    ensure
      LibCrypto.beryl_rsa_spec_evp_pkey_ctx_free(context)
    end
  end

  def self.digest_of(hash_name : String, message : Bytes) : Bytes
    OpenSSL::Digest.new(hash_name).update(message).final
  end

  def self.set_signature_parameters(context : Void*, hash_name : String, salt_bytesize : Int32?) : Nil
    evp_md = LibcryptoDifferential.libcrypto_digest(hash_name)
    if salt_bytesize
      check LibCrypto.beryl_rsa_spec_set_rsa_padding(context, RSA_PKCS1_PSS_PADDING)
      check LibCrypto.beryl_rsa_spec_set_signature_md(context, evp_md)
      check LibCrypto.beryl_rsa_spec_set_rsa_mgf1_md(context, evp_md)
      check LibCrypto.beryl_rsa_spec_set_rsa_pss_saltlen(context, salt_bytesize)
    else
      check LibCrypto.beryl_rsa_spec_set_rsa_padding(context, RSA_PKCS1_PADDING)
      check LibCrypto.beryl_rsa_spec_set_signature_md(context, evp_md)
    end
  end

  # libcrypto's signature of *message*: PSS when *salt_bytesize* is given,
  # PKCS #1 v1.5 otherwise.
  def self.libcrypto_sign(libcrypto_key : Void*, hash_name : String, message : Bytes, salt_bytesize : Int32?, modulus_bytesize : Int32) : Bytes
    with_context(libcrypto_key) do |context|
      check LibCrypto.beryl_rsa_spec_evp_pkey_sign_init(context)
      set_signature_parameters(context, hash_name, salt_bytesize)
      digest = digest_of(hash_name, message)
      signature = Bytes.new(modulus_bytesize)
      signature_bytesize = LibC::SizeT.new(signature.size)
      check LibCrypto.beryl_rsa_spec_evp_pkey_sign(context, signature, pointerof(signature_bytesize), digest, digest.size)
      signature[0, signature_bytesize]
    end
  end

  def self.libcrypto_verifies?(libcrypto_key : Void*, hash_name : String, message : Bytes, signature : Bytes, salt_bytesize : Int32?) : Bool
    with_context(libcrypto_key) do |context|
      check LibCrypto.beryl_rsa_spec_evp_pkey_verify_init(context)
      set_signature_parameters(context, hash_name, salt_bytesize)
      digest = digest_of(hash_name, message)
      LibCrypto.beryl_rsa_spec_evp_pkey_verify(context, signature, signature.size, digest, digest.size) == 1
    end
  end

  def self.set_oaep_parameters(context : Void*, hash_name : String, label : Bytes) : Nil
    evp_md = LibcryptoDifferential.libcrypto_digest(hash_name)
    check LibCrypto.beryl_rsa_spec_set_rsa_padding(context, RSA_PKCS1_OAEP_PADDING)
    check LibCrypto.beryl_rsa_spec_set_rsa_oaep_md(context, evp_md)
    check LibCrypto.beryl_rsa_spec_set_rsa_mgf1_md(context, evp_md)
    return if label.empty?

    # The context takes the label and frees it, so it is libcrypto's memory.
    owned_label = LibCrypto.beryl_rsa_spec_crypto_malloc(label.size, "rsa_differential", 0)
    label.copy_to(owned_label.as(UInt8*), label.size)
    check LibCrypto.beryl_rsa_spec_set0_rsa_oaep_label(context, owned_label, label.size)
  end

  def self.libcrypto_encrypt(libcrypto_key : Void*, hash_name : String, message : Bytes, label : Bytes, modulus_bytesize : Int32) : Bytes
    with_context(libcrypto_key) do |context|
      check LibCrypto.beryl_rsa_spec_evp_pkey_encrypt_init(context)
      set_oaep_parameters(context, hash_name, label)
      ciphertext = Bytes.new(modulus_bytesize)
      ciphertext_bytesize = LibC::SizeT.new(ciphertext.size)
      check LibCrypto.beryl_rsa_spec_evp_pkey_encrypt(context, ciphertext, pointerof(ciphertext_bytesize), message, message.size)
      ciphertext[0, ciphertext_bytesize]
    end
  end

  # Returns the message, or nil when libcrypto refuses the ciphertext.
  def self.libcrypto_decrypt(libcrypto_key : Void*, hash_name : String, ciphertext : Bytes, label : Bytes, modulus_bytesize : Int32) : Bytes?
    with_context(libcrypto_key) do |context|
      check LibCrypto.beryl_rsa_spec_evp_pkey_decrypt_init(context)
      set_oaep_parameters(context, hash_name, label)
      message = Bytes.new(modulus_bytesize)
      message_bytesize = LibC::SizeT.new(message.size)
      if LibCrypto.beryl_rsa_spec_evp_pkey_decrypt(context, message, pointerof(message_bytesize), ciphertext, ciphertext.size) == 1
        message[0, message_bytesize]
      end
    end
  end

  # Runs the block with the Beryl hash class for the libcrypto *hash_name*.
  macro with_beryl_hash(hash_name, &block)
    case {{ hash_name }}
    {% for pair in [{"SHA1", "Beryl::Crypto::Compatibility::SHA1"}, {"SHA224", "Beryl::Crypto::V1::SHA224"},
                    {"SHA256", "Beryl::Crypto::V1::SHA256"}, {"SHA384", "Beryl::Crypto::V1::SHA384"},
                    {"SHA512", "Beryl::Crypto::V1::SHA512"}, {"SHA512-256", "Beryl::Crypto::V1::SHA512_256"}] %}
    when {{ pair[0] }}
      {{ block.args[0] }} = {{ pair[1].id }}
      {{ block.body }}
    {% end %}
    else
      raise "no Beryl hash for #{{{ hash_name }}}"
    end
  end

  # As `with_beryl_hash`, for the SHA-2 hashes Beryl signs with.
  macro with_beryl_signing_hash(hash_name, &block)
    case {{ hash_name }}
    {% for pair in [{"SHA224", "Beryl::Crypto::V1::SHA224"},
                    {"SHA256", "Beryl::Crypto::V1::SHA256"}, {"SHA384", "Beryl::Crypto::V1::SHA384"},
                    {"SHA512", "Beryl::Crypto::V1::SHA512"}, {"SHA512-256", "Beryl::Crypto::V1::SHA512_256"}] %}
    when {{ pair[0] }}
      {{ block.args[0] }} = {{ pair[1].id }}
      {{ block.body }}
    {% end %}
    else
      raise "no Beryl hash for #{{{ hash_name }}}"
    end
  end

  # Returns *bytes* mutated by the case generator: one bit flipped (most
  # cases), or every byte 0xff, a value at or above any modulus of that size.
  def self.mutated(bytes : Bytes, generator : Random::PCG32) : Bytes
    copy = bytes.dup
    if copy.empty? || generator.rand(16) == 0
      copy.fill(0xff_u8)
    else
      copy[generator.rand(copy.size)] ^= 1_u8 << generator.rand(8)
    end
    copy
  end

  def self.describe_run(algorithm : String, case_count : Int32, key_pool_size : Int32) : Nil
    settings = LibcryptoDifferential.settings
    STDOUT.puts "differential #{algorithm}: seed #{settings.seed}, cases #{settings.first_case}...#{settings.first_case + case_count}, " \
                "#{key_pool_size} keys from libcrypto, against #{String.new(LibCrypto.beryl_spec_openssl_version(0))}"
  end

  def self.report_mismatch(algorithm : String, case_number : Int32, key_pair : KeyPair, detail : String) : NoReturn
    settings = LibcryptoDifferential.settings
    fail "#{algorithm} differs from libcrypto at case #{case_number} with seed #{settings.seed}: #{detail}; #{key_pair.describe}"
  end

  def self.random_bytes(generator : Random::PCG32, bytesize : Int32) : Bytes
    bytes = Bytes.new(bytesize)
    generator.random_bytes(bytes)
    bytes
  end
end

if RequestedSpecTag.includes?("differential")
  describe "differential of RSA against libcrypto", tags: "differential" do
    {% for bit_count in [2_048, 3_072, 4_096] %}
      it "RSA-{{ bit_count }} PKCS#1 v1.5 matches libcrypto: equal signatures, each verifies the other, same verdict on mutations" do
        algorithm = "RSA-{{ bit_count }} PKCS#1 v1.5"
        case_count = LibcryptoRsaDifferential.case_count_for({{ bit_count }})
        pool_size = LibcryptoRsaDifferential::KEY_POOL_SIZE_BY_BIT_COUNT[{{ bit_count }}]
        LibcryptoRsaDifferential.describe_run(algorithm, case_count, pool_size)
        list_of_key_pairs = Array.new(pool_size) { LibcryptoRsaDifferential.generate_key_pair({{ bit_count }}) }
        first_case = LibcryptoDifferential.settings.first_case
        mutation_count = 0
        (first_case...(first_case + case_count)).each do |case_number|
          generator = LibcryptoDifferential.generator_for(4_000 + {{ bit_count }}, case_number)
          key_pair = list_of_key_pairs[generator.rand(pool_size)]
          hash_name = LibcryptoRsaDifferential::LIST_OF_SIGNING_HASH_NAMES.sample(generator)
          message = LibcryptoRsaDifferential.random_bytes(generator, generator.rand(0..LibcryptoRsaDifferential::LARGEST_MESSAGE_BYTESIZE))
          modulus_bytesize = key_pair.beryl_key.modulus_bytesize
          public_key = key_pair.beryl_key.public_key

          libcrypto_signature = LibcryptoRsaDifferential.libcrypto_sign(key_pair.libcrypto_key, hash_name, message, nil, modulus_bytesize)
          LibcryptoRsaDifferential.with_beryl_signing_hash(hash_name) do |hash_function|
            beryl_signature = key_pair.beryl_key.sign_with_pkcs1(message, hash_function: hash_function)
            unless beryl_signature == libcrypto_signature
              LibcryptoRsaDifferential.report_mismatch(algorithm, case_number, key_pair, "#{hash_name} signatures differ")
            end
            unless public_key.verify_pkcs1_signature(message, libcrypto_signature, hash_function: hash_function) &&
                   LibcryptoRsaDifferential.libcrypto_verifies?(key_pair.libcrypto_key, hash_name, message, beryl_signature, nil)
              LibcryptoRsaDifferential.report_mismatch(algorithm, case_number, key_pair, "#{hash_name} signature not verified")
            end

            mutated_signature, mutated_message = generator.next_bool ? {LibcryptoRsaDifferential.mutated(beryl_signature, generator), message} : {beryl_signature, LibcryptoRsaDifferential.mutated(message, generator)}
            beryl_verdict = public_key.verify_pkcs1_signature(mutated_message, mutated_signature, hash_function: hash_function)
            libcrypto_verdict = LibcryptoRsaDifferential.libcrypto_verifies?(key_pair.libcrypto_key, hash_name, mutated_message, mutated_signature, nil)
            unless beryl_verdict == libcrypto_verdict
              LibcryptoRsaDifferential.report_mismatch(algorithm, case_number, key_pair, "#{hash_name} mutation: Beryl #{beryl_verdict}, libcrypto #{libcrypto_verdict}")
            end
            mutation_count += 1
          end
        end
        STDOUT.puts "differential #{algorithm}: #{case_count} cases, #{mutation_count} mutations, 0 mismatches"
      end

      it "RSA-{{ bit_count }} PSS matches libcrypto: each verifies the other, same verdict on mutations" do
        algorithm = "RSA-{{ bit_count }} PSS"
        case_count = LibcryptoRsaDifferential.case_count_for({{ bit_count }})
        pool_size = LibcryptoRsaDifferential::KEY_POOL_SIZE_BY_BIT_COUNT[{{ bit_count }}]
        LibcryptoRsaDifferential.describe_run(algorithm, case_count, pool_size)
        list_of_key_pairs = Array.new(pool_size) { LibcryptoRsaDifferential.generate_key_pair({{ bit_count }}) }
        first_case = LibcryptoDifferential.settings.first_case
        mutation_count = 0
        (first_case...(first_case + case_count)).each do |case_number|
          generator = LibcryptoDifferential.generator_for(5_000 + {{ bit_count }}, case_number)
          key_pair = list_of_key_pairs[generator.rand(pool_size)]
          hash_name = LibcryptoRsaDifferential::LIST_OF_SIGNING_HASH_NAMES.sample(generator)
          message = LibcryptoRsaDifferential.random_bytes(generator, generator.rand(0..LibcryptoRsaDifferential::LARGEST_MESSAGE_BYTESIZE))
          modulus_bytesize = key_pair.beryl_key.modulus_bytesize
          public_key = key_pair.beryl_key.public_key

          LibcryptoRsaDifferential.with_beryl_signing_hash(hash_name) do |hash_function|
            digest_bytesize = hash_function.new.digest_size
            largest_salt_bytesize = (key_pair.beryl_key.modulus_bit_count - 1 + 7) // 8 - digest_bytesize - 2
            salt_bytesize = case generator.rand(4)
                            when 0 then 0
                            when 1 then digest_bytesize
                            when 2 then largest_salt_bytesize
                            else        generator.rand(0..largest_salt_bytesize)
                            end
            beryl_signature = key_pair.beryl_key.sign_with_pss(message, hash_function: hash_function, salt_bytesize: salt_bytesize)
            libcrypto_signature = LibcryptoRsaDifferential.libcrypto_sign(key_pair.libcrypto_key, hash_name, message, salt_bytesize, modulus_bytesize)
            unless LibcryptoRsaDifferential.libcrypto_verifies?(key_pair.libcrypto_key, hash_name, message, beryl_signature, salt_bytesize)
              LibcryptoRsaDifferential.report_mismatch(algorithm, case_number, key_pair, "#{hash_name} salt #{salt_bytesize}: libcrypto refuses the Beryl signature")
            end
            unless public_key.verify_pss_signature(message, libcrypto_signature, hash_function: hash_function, salt_bytesize: salt_bytesize)
              LibcryptoRsaDifferential.report_mismatch(algorithm, case_number, key_pair, "#{hash_name} salt #{salt_bytesize}: Beryl refuses the libcrypto signature")
            end

            mutated_signature, mutated_message = generator.next_bool ? {LibcryptoRsaDifferential.mutated(libcrypto_signature, generator), message} : {libcrypto_signature, LibcryptoRsaDifferential.mutated(message, generator)}
            beryl_verdict = public_key.verify_pss_signature(mutated_message, mutated_signature, hash_function: hash_function, salt_bytesize: salt_bytesize)
            libcrypto_verdict = LibcryptoRsaDifferential.libcrypto_verifies?(key_pair.libcrypto_key, hash_name, mutated_message, mutated_signature, salt_bytesize)
            unless beryl_verdict == libcrypto_verdict
              LibcryptoRsaDifferential.report_mismatch(algorithm, case_number, key_pair, "#{hash_name} mutation: Beryl #{beryl_verdict}, libcrypto #{libcrypto_verdict}")
            end
            mutation_count += 1
          end
        end
        STDOUT.puts "differential #{algorithm}: #{case_count} cases, #{mutation_count} mutations, 0 mismatches"
      end

      it "RSA-{{ bit_count }} OAEP matches libcrypto: each decrypts the other, same verdict on mutations" do
        algorithm = "RSA-{{ bit_count }} OAEP"
        case_count = LibcryptoRsaDifferential.case_count_for({{ bit_count }})
        pool_size = LibcryptoRsaDifferential::KEY_POOL_SIZE_BY_BIT_COUNT[{{ bit_count }}]
        LibcryptoRsaDifferential.describe_run(algorithm, case_count, pool_size)
        list_of_key_pairs = Array.new(pool_size) { LibcryptoRsaDifferential.generate_key_pair({{ bit_count }}) }
        first_case = LibcryptoDifferential.settings.first_case
        mutation_count = 0
        (first_case...(first_case + case_count)).each do |case_number|
          generator = LibcryptoDifferential.generator_for(6_000 + {{ bit_count }}, case_number)
          key_pair = list_of_key_pairs[generator.rand(pool_size)]
          hash_name = LibcryptoRsaDifferential::LIST_OF_OAEP_HASH_NAMES.sample(generator)
          modulus_bytesize = key_pair.beryl_key.modulus_bytesize
          public_key = key_pair.beryl_key.public_key
          label = generator.rand(2) == 0 ? Bytes.empty : LibcryptoRsaDifferential.random_bytes(generator, generator.rand(1..LibcryptoRsaDifferential::LARGEST_LABEL_BYTESIZE))

          LibcryptoRsaDifferential.with_beryl_hash(hash_name) do |hash_function|
            largest_message_bytesize = modulus_bytesize - 2 * hash_function.new.digest_size - 2
            message = LibcryptoRsaDifferential.random_bytes(generator, generator.rand(0..largest_message_bytesize))
            beryl_ciphertext = public_key.encrypt_with_oaep(message, hash_function: hash_function, label: label)
            libcrypto_ciphertext = LibcryptoRsaDifferential.libcrypto_encrypt(key_pair.libcrypto_key, hash_name, message, label, modulus_bytesize)
            unless LibcryptoRsaDifferential.libcrypto_decrypt(key_pair.libcrypto_key, hash_name, beryl_ciphertext, label, modulus_bytesize) == message
              LibcryptoRsaDifferential.report_mismatch(algorithm, case_number, key_pair, "#{hash_name}: libcrypto does not decrypt the Beryl ciphertext to the message")
            end
            unless key_pair.beryl_key.decrypt_with_oaep(libcrypto_ciphertext, hash_function: hash_function, label: label) == message
              LibcryptoRsaDifferential.report_mismatch(algorithm, case_number, key_pair, "#{hash_name}: Beryl does not decrypt the libcrypto ciphertext to the message")
            end

            mutated_ciphertext, mutated_label = generator.rand(4) == 0 ? {libcrypto_ciphertext, LibcryptoRsaDifferential.mutated(label, generator)} : {LibcryptoRsaDifferential.mutated(libcrypto_ciphertext, generator), label}
            beryl_result = key_pair.beryl_key.decrypt_with_oaep(mutated_ciphertext, hash_function: hash_function, label: mutated_label)
            libcrypto_result = LibcryptoRsaDifferential.libcrypto_decrypt(key_pair.libcrypto_key, hash_name, mutated_ciphertext, mutated_label, modulus_bytesize)
            unless beryl_result == libcrypto_result
              LibcryptoRsaDifferential.report_mismatch(algorithm, case_number, key_pair, "#{hash_name} mutation: Beryl #{beryl_result.nil? ? "refuses" : "decrypts"}, libcrypto #{libcrypto_result.nil? ? "refuses" : "decrypts"}")
            end
            mutation_count += 1
          end
        end
        STDOUT.puts "differential #{algorithm}: #{case_count} cases, #{mutation_count} mutations, 0 mismatches"
      end
    {% end %}
  end
end
