require "./libcrypto_differential_spec"

# Differential test of Beryl's curves against libcrypto (OpenSSL 4.1.0).
#
#     crystal-alpha spec --release --tag differential -e "curve X25519 "
#
# The names are `curve X25519`, `curve Ed25519`, `curve P-256 ECDH`,
# `curve P-256 ECDSA` and `curve P-384 ECDSA`. Each case draws its inputs
# from a generator seeded by the run seed and the case number, so a failing
# case replays alone (see `LibcryptoDifferential`). Without
# BERYL_DIFFERENTIAL_CASE_COUNT, X25519 runs 1,000,000 cases and the others
# 200,000; every Ed25519 and ECDSA case also checks one altered signature,
# message or key, so the altered cases number as many again.
lib LibCrypto
  fun beryl_curve_evp_pkey_new_raw_private_key = EVP_PKEY_new_raw_private_key(type : LibC::Int, engine : Void*, key : UInt8*, key_bytesize : LibC::SizeT) : Void*
  fun beryl_curve_evp_pkey_new_raw_public_key = EVP_PKEY_new_raw_public_key(type : LibC::Int, engine : Void*, key : UInt8*, key_bytesize : LibC::SizeT) : Void*
  fun beryl_curve_evp_pkey_get_raw_public_key = EVP_PKEY_get_raw_public_key(key : Void*, public_key : UInt8*, bytesize : LibC::SizeT*) : LibC::Int
  fun beryl_curve_evp_pkey_free = EVP_PKEY_free(key : Void*)
  fun beryl_curve_evp_pkey_ctx_new = EVP_PKEY_CTX_new(key : Void*, engine : Void*) : Void*
  fun beryl_curve_evp_pkey_ctx_new_from_name = EVP_PKEY_CTX_new_from_name(library_context : Void*, name : LibC::Char*, properties : LibC::Char*) : Void*
  fun beryl_curve_evp_pkey_ctx_free = EVP_PKEY_CTX_free(context : Void*)
  fun beryl_curve_evp_pkey_derive_init = EVP_PKEY_derive_init(context : Void*) : LibC::Int
  fun beryl_curve_evp_pkey_derive_set_peer_ex = EVP_PKEY_derive_set_peer_ex(context : Void*, peer : Void*, validate_peer : LibC::Int) : LibC::Int
  fun beryl_curve_evp_pkey_derive = EVP_PKEY_derive(context : Void*, key : UInt8*, bytesize : LibC::SizeT*) : LibC::Int
  fun beryl_curve_evp_pkey_keygen_init = EVP_PKEY_keygen_init(context : Void*) : LibC::Int
  fun beryl_curve_evp_pkey_ctx_set_group_name = EVP_PKEY_CTX_set_group_name(context : Void*, name : LibC::Char*) : LibC::Int
  fun beryl_curve_evp_pkey_generate = EVP_PKEY_generate(context : Void*, key : Void**) : LibC::Int
  fun beryl_curve_evp_pkey_get_bn_param = EVP_PKEY_get_bn_param(key : Void*, name : LibC::Char*, number : Void**) : LibC::Int
  fun beryl_curve_evp_pkey_get_octet_string_param = EVP_PKEY_get_octet_string_param(key : Void*, name : LibC::Char*, buffer : UInt8*, capacity : LibC::SizeT, bytesize : LibC::SizeT*) : LibC::Int
  fun beryl_curve_evp_pkey_fromdata_init = EVP_PKEY_fromdata_init(context : Void*) : LibC::Int
  fun beryl_curve_evp_pkey_fromdata = EVP_PKEY_fromdata(context : Void*, key : Void**, selection : LibC::Int, parameters : Void*) : LibC::Int
  fun beryl_curve_bn_bn2binpad = BN_bn2binpad(number : Void*, output : UInt8*, bytesize : LibC::Int) : LibC::Int
  fun beryl_curve_bn_free = BN_free(number : Void*)
  fun beryl_curve_param_bld_new = OSSL_PARAM_BLD_new : Void*
  fun beryl_curve_param_bld_push_utf8_string = OSSL_PARAM_BLD_push_utf8_string(builder : Void*, key : LibC::Char*, value : LibC::Char*, bytesize : LibC::SizeT) : LibC::Int
  fun beryl_curve_param_bld_push_octet_string = OSSL_PARAM_BLD_push_octet_string(builder : Void*, key : LibC::Char*, value : Void*, bytesize : LibC::SizeT) : LibC::Int
  fun beryl_curve_param_bld_to_param = OSSL_PARAM_BLD_to_param(builder : Void*) : Void*
  fun beryl_curve_param_bld_free = OSSL_PARAM_BLD_free(builder : Void*)
  fun beryl_curve_param_free = OSSL_PARAM_free(parameters : Void*)
  fun beryl_curve_digest_sign_init = EVP_DigestSignInit(context : EVP_MD_CTX, key_context : Void**, digest : Void*, engine : Void*, key : Void*) : LibC::Int
  fun beryl_curve_digest_sign = EVP_DigestSign(context : EVP_MD_CTX, signature : UInt8*, bytesize : LibC::SizeT*, message : UInt8*, message_bytesize : LibC::SizeT) : LibC::Int
  fun beryl_curve_digest_verify_init = EVP_DigestVerifyInit(context : EVP_MD_CTX, key_context : Void**, digest : Void*, engine : Void*, key : Void*) : LibC::Int
  fun beryl_curve_digest_verify = EVP_DigestVerify(context : EVP_MD_CTX, signature : UInt8*, bytesize : LibC::SizeT, message : UInt8*, message_bytesize : LibC::SizeT) : LibC::Int
  fun beryl_curve_err_clear_error = ERR_clear_error
end

module LibcryptoCurveDifferential
  NID_X25519        = 1034
  NID_ED25519       = 1087
  SELECT_PUBLIC_KEY = 0x86 # EVP_PKEY_PUBLIC_KEY
  LARGEST_MESSAGE   =  300
  ALTERATION_KINDS  =    6

  # The points of small order on Curve25519 and some values above p, which
  # every implementation must handle (RFC 7748 §5 accepts all 32 bytes).
  LIST_OF_UNUSUAL_U_COORDINATES = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  ].map(&.hexbytes)

  def self.case_count(default : Int32) : Int32
    ENV["BERYL_DIFFERENTIAL_CASE_COUNT"]?.try(&.to_i) || default
  end

  def self.check(result : LibC::Int, what : String) : Nil
    raise "libcrypto failed: #{what}" unless result == 1
  end

  def self.random_bytes(generator : Random::PCG32, bytesize : Int32) : Bytes
    bytes = Bytes.new(bytesize)
    generator.random_bytes(bytes)
    bytes
  end

  # Returns libcrypto's X25519 shared secret, or nil when it refuses one.
  def self.libcrypto_x25519(private_key : Bytes, peer : Bytes) : Bytes?
    key = LibCrypto.beryl_curve_evp_pkey_new_raw_private_key(NID_X25519, nil, private_key, private_key.size)
    peer_key = LibCrypto.beryl_curve_evp_pkey_new_raw_public_key(NID_X25519, nil, peer, peer.size)
    derive(key, peer_key, validate_peer: 0)
  ensure
    LibCrypto.beryl_curve_evp_pkey_free(key) if key
    LibCrypto.beryl_curve_evp_pkey_free(peer_key) if peer_key
  end

  def self.libcrypto_x25519_public_key(private_key : Bytes) : Bytes
    key = LibCrypto.beryl_curve_evp_pkey_new_raw_private_key(NID_X25519, nil, private_key, private_key.size)
    raw_public_key(key)
  ensure
    LibCrypto.beryl_curve_evp_pkey_free(key) if key
  end

  def self.raw_public_key(key : Void*) : Bytes
    public_key = Bytes.new(32)
    bytesize = LibC::SizeT.new(32)
    check LibCrypto.beryl_curve_evp_pkey_get_raw_public_key(key, public_key, pointerof(bytesize)), "get_raw_public_key"
    public_key
  end

  def self.derive(key : Void*, peer : Void*, validate_peer : Int32) : Bytes?
    context = LibCrypto.beryl_curve_evp_pkey_ctx_new(key, nil)
    begin
      check LibCrypto.beryl_curve_evp_pkey_derive_init(context), "derive_init"
      unless LibCrypto.beryl_curve_evp_pkey_derive_set_peer_ex(context, peer, validate_peer) == 1
        LibCrypto.beryl_curve_err_clear_error
        return nil
      end
      shared = Bytes.new(64)
      bytesize = LibC::SizeT.new(64)
      unless LibCrypto.beryl_curve_evp_pkey_derive(context, shared, pointerof(bytesize)) == 1
        LibCrypto.beryl_curve_err_clear_error
        return nil
      end
      shared[0, bytesize].dup
    ensure
      LibCrypto.beryl_curve_evp_pkey_ctx_free(context)
    end
  end

  # Signs *message* with libcrypto (a null digest for Ed25519).
  def self.libcrypto_sign(key : Void*, digest : Void*, message : Bytes) : Bytes
    context = LibCrypto.evp_md_ctx_new
    begin
      check LibCrypto.beryl_curve_digest_sign_init(context, nil, digest, nil, key), "DigestSignInit"
      signature = Bytes.new(160)
      bytesize = LibC::SizeT.new(160)
      check LibCrypto.beryl_curve_digest_sign(context, signature, pointerof(bytesize), message, message.size), "DigestSign"
      signature[0, bytesize].dup
    ensure
      LibCrypto.evp_md_ctx_free(context)
    end
  end

  def self.libcrypto_verify(key : Void*, digest : Void*, message : Bytes, signature : Bytes) : Bool
    context = LibCrypto.evp_md_ctx_new
    begin
      check LibCrypto.beryl_curve_digest_verify_init(context, nil, digest, nil, key), "DigestVerifyInit"
      verdict = LibCrypto.beryl_curve_digest_verify(context, signature, signature.size, message, message.size) == 1
      LibCrypto.beryl_curve_err_clear_error
      verdict
    ensure
      LibCrypto.evp_md_ctx_free(context)
    end
  end

  # A new libcrypto key pair on the named group.
  def self.generate_ec_key(group : String) : Void*
    context = LibCrypto.beryl_curve_evp_pkey_ctx_new_from_name(nil, "EC", nil)
    begin
      check LibCrypto.beryl_curve_evp_pkey_keygen_init(context), "keygen_init"
      check LibCrypto.beryl_curve_evp_pkey_ctx_set_group_name(context, group), "set_group_name"
      key = Pointer(Void).null
      check LibCrypto.beryl_curve_evp_pkey_generate(context, pointerof(key)), "generate"
      key
    ensure
      LibCrypto.beryl_curve_evp_pkey_ctx_free(context)
    end
  end

  def self.ec_private_scalar(key : Void*, bytesize : Int32) : Bytes
    number = Pointer(Void).null
    check LibCrypto.beryl_curve_evp_pkey_get_bn_param(key, "priv", pointerof(number)), "get priv"
    scalar = Bytes.new(bytesize)
    LibCrypto.beryl_curve_bn_bn2binpad(number, scalar, bytesize)
    LibCrypto.beryl_curve_bn_free(number)
    scalar
  end

  def self.ec_public_point(key : Void*) : Bytes
    point = Bytes.new(200)
    bytesize = LibC::SizeT.new(0)
    check LibCrypto.beryl_curve_evp_pkey_get_octet_string_param(key, "encoded-pub-key", point, point.size, pointerof(bytesize)), "get pub"
    point[0, bytesize].dup
  end

  # libcrypto's public key for an encoded point, or nil when it refuses it.
  def self.ec_public_key(group : String, point : Bytes) : Void*?
    builder = LibCrypto.beryl_curve_param_bld_new
    LibCrypto.beryl_curve_param_bld_push_utf8_string(builder, "group", group, group.bytesize)
    LibCrypto.beryl_curve_param_bld_push_octet_string(builder, "pub", point, point.size)
    parameters = LibCrypto.beryl_curve_param_bld_to_param(builder)
    context = LibCrypto.beryl_curve_evp_pkey_ctx_new_from_name(nil, "EC", nil)
    key = Pointer(Void).null
    begin
      check LibCrypto.beryl_curve_evp_pkey_fromdata_init(context), "fromdata_init"
      unless LibCrypto.beryl_curve_evp_pkey_fromdata(context, pointerof(key), SELECT_PUBLIC_KEY, parameters) == 1
        LibCrypto.beryl_curve_err_clear_error
        return nil
      end
      key
    ensure
      LibCrypto.beryl_curve_evp_pkey_ctx_free(context)
      LibCrypto.beryl_curve_param_free(parameters)
      LibCrypto.beryl_curve_param_bld_free(builder)
    end
  end

  # Whether *point* is in X9.62's hybrid form (0x06 or 0x07 || X || Y).
  def self.hybrid_point?(point : Bytes) : Bool
    point.size > 1 && point.size.odd? && (point[0] == 0x06_u8 || point[0] == 0x07_u8)
  end

  # Beryl's verdict on *signature*, with false for a key it refuses to
  # decode. The block decodes the key on the curve under test.
  def self.beryl_ecdsa_verdict(point : Bytes, message : Bytes, signature : Bytes, & : Bytes -> _) : Bool
    yield(point).verify(message, signature)
  rescue Beryl::Crypto::InvalidPublicKey
    false
  end

  # Alters one of signature, message or key bytes; returns the altered
  # triple. Kinds: flip one bit of the signature, of the message, or of the
  # key; replace the signature's second half; add the group order to the
  # second half (signature malleability); truncate the signature.
  def self.alter(generator : Random::PCG32, signature : Bytes, message : Bytes, key : Bytes, group_order : Bytes?) : {Bytes, Bytes, Bytes}
    signature = signature.dup
    message = message.dup
    key = key.dup
    case generator.rand(ALTERATION_KINDS)
    when 0
      index = generator.rand(signature.size)
      signature[index] ^= (1_u8 << generator.rand(8))
    when 1
      if message.empty?
        message = Bytes[generator.rand(256).to_u8]
      else
        index = generator.rand(message.size)
        message[index] ^= (1_u8 << generator.rand(8))
      end
    when 2
      index = generator.rand(key.size)
      key[index] ^= (1_u8 << generator.rand(8))
    when 3
      half = signature.size // 2
      generator.random_bytes(signature[half, signature.size - half])
    when 4
      order = group_order
      if order && signature.size == 64
        # S + L, little-endian (Ed25519).
        carry = 0
        32.times do |index|
          sum = signature[32 + index].to_i32 + order[index] + carry
          signature[32 + index] = (sum & 0xff).to_u8
          carry = sum >> 8
        end
      else
        signature[signature.size - 1] ^= 0x80_u8
      end
    else
      signature = signature[0, generator.rand(signature.size)].dup
    end
    {signature, message, key}
  end
end

if RequestedSpecTag.includes?("differential")
  describe "differential against libcrypto", tags: "differential" do
    it "curve X25519 equals libcrypto on random keys and peer values" do
      case_count = LibcryptoCurveDifferential.case_count(1_000_000)
      LibcryptoDifferential.describe_run("curve X25519", case_count)
      settings = LibcryptoDifferential.settings
      refused = 0
      (settings.first_case...(settings.first_case + case_count)).each do |case_number|
        generator = LibcryptoDifferential.generator_for(101, case_number)
        private_bytes = LibcryptoCurveDifferential.random_bytes(generator, 32)
        peer = if generator.rand(64) == 0
                 LibcryptoCurveDifferential::LIST_OF_UNUSUAL_U_COORDINATES.sample(generator)
               else
                 LibcryptoCurveDifferential.random_bytes(generator, 32)
               end
        private_key = Beryl::Crypto::V1::X25519::PrivateKey.new(private_bytes)
        beryl_public = private_key.public_key.to_slice
        libcrypto_public = LibcryptoCurveDifferential.libcrypto_x25519_public_key(private_bytes)
        LibcryptoDifferential.report_mismatch("curve X25519", case_number, "public key #{beryl_public.hexstring} vs #{libcrypto_public.hexstring}") unless beryl_public == libcrypto_public
        beryl_shared = private_key.shared_secret(Beryl::Crypto::V1::X25519::PublicKey.new(peer))
        libcrypto_shared = LibcryptoCurveDifferential.libcrypto_x25519(private_bytes, peer)
        refused += 1 if beryl_shared.nil?
        unless beryl_shared == libcrypto_shared
          LibcryptoDifferential.report_mismatch("curve X25519", case_number, "shared secret #{beryl_shared.try(&.hexstring)} vs #{libcrypto_shared.try(&.hexstring)}")
        end
      end
      STDOUT.puts "curve X25519: #{case_count} cases, 0 mismatches (#{refused} all-zero shared secrets refused by both)"
    end

    it "curve Ed25519 equals libcrypto on keys, signatures and verdicts" do
      case_count = LibcryptoCurveDifferential.case_count(200_000)
      LibcryptoDifferential.describe_run("curve Ed25519", case_count)
      settings = LibcryptoDifferential.settings
      group_order = Beryl::Crypto::V1::Edwards25519Group::GROUP_ORDER
      altered_accepted = 0
      (settings.first_case...(settings.first_case + case_count)).each do |case_number|
        generator = LibcryptoDifferential.generator_for(102, case_number)
        seed = LibcryptoCurveDifferential.random_bytes(generator, 32)
        message = LibcryptoCurveDifferential.random_bytes(generator, generator.rand(0..LibcryptoCurveDifferential::LARGEST_MESSAGE))
        signing_key = Beryl::Crypto::V1::Ed25519::SigningKey.new(seed)
        libcrypto_key = LibCrypto.beryl_curve_evp_pkey_new_raw_private_key(LibcryptoCurveDifferential::NID_ED25519, nil, seed, 32)
        begin
          public_key = signing_key.verification_key.to_slice
          libcrypto_public = LibcryptoCurveDifferential.raw_public_key(libcrypto_key)
          LibcryptoDifferential.report_mismatch("curve Ed25519", case_number, "public key") unless public_key == libcrypto_public
          signature = signing_key.sign(message)
          libcrypto_signature = LibcryptoCurveDifferential.libcrypto_sign(libcrypto_key, Pointer(Void).null, message)
          LibcryptoDifferential.report_mismatch("curve Ed25519", case_number, "signature") unless signature == libcrypto_signature
          unless LibcryptoCurveDifferential.libcrypto_verify(libcrypto_key, Pointer(Void).null, message, signature) &&
                 signing_key.verification_key.verify(message, libcrypto_signature)
            LibcryptoDifferential.report_mismatch("curve Ed25519", case_number, "a valid signature was refused")
          end

          altered_signature, altered_message, altered_key = LibcryptoCurveDifferential.alter(generator, signature, message, public_key, group_order)
          beryl_verdict = begin
            Beryl::Crypto::V1::Ed25519::VerificationKey.new(altered_key).verify(altered_message, altered_signature)
          rescue Beryl::Crypto::InvalidPublicKey
            false
          end
          libcrypto_altered_key = LibCrypto.beryl_curve_evp_pkey_new_raw_public_key(LibcryptoCurveDifferential::NID_ED25519, nil, altered_key, 32)
          libcrypto_verdict = !libcrypto_altered_key.null? && LibcryptoCurveDifferential.libcrypto_verify(libcrypto_altered_key, Pointer(Void).null, altered_message, altered_signature)
          LibCrypto.beryl_curve_evp_pkey_free(libcrypto_altered_key) unless libcrypto_altered_key.null?
          altered_accepted += 1 if beryl_verdict
          unless beryl_verdict == libcrypto_verdict
            LibcryptoDifferential.report_mismatch("curve Ed25519", case_number,
              "altered case: Beryl #{beryl_verdict}, libcrypto #{libcrypto_verdict} (key #{altered_key.hexstring}, signature #{altered_signature.hexstring})")
          end
        ensure
          LibCrypto.beryl_curve_evp_pkey_free(libcrypto_key)
        end
      end
      STDOUT.puts "curve Ed25519: #{case_count} cases and #{case_count} altered cases, 0 mismatches (#{altered_accepted} altered cases accepted by both)"
    end

    it "curve Ed25519 equals libcrypto on every Wycheproof case" do
      test_file = Wycheproof::TestFile(Wycheproof::EddsaVerifyTestGroup).from_json(VectorFile.read("wycheproof/ed25519_test.json"))
      cases_run = 0
      test_file.list_of_test_groups.each do |test_group|
        encoded_key = test_group.public_key.encoded.hexbytes
        verification_key = Beryl::Crypto::V1::Ed25519::VerificationKey.new(encoded_key)
        libcrypto_key = LibCrypto.beryl_curve_evp_pkey_new_raw_public_key(LibcryptoCurveDifferential::NID_ED25519, nil, encoded_key, 32)
        test_group.list_of_tests.each do |test|
          message = test.message.hexbytes
          signature = test.signature.hexbytes
          beryl_verdict = verification_key.verify(message, signature)
          libcrypto_verdict = LibcryptoCurveDifferential.libcrypto_verify(libcrypto_key, Pointer(Void).null, message, signature)
          unless beryl_verdict == libcrypto_verdict
            fail "ed25519_test.json tcId #{test.test_case_id} (#{test.comment}): Beryl #{beryl_verdict}, libcrypto #{libcrypto_verdict}"
          end
          cases_run += 1
        end
        LibCrypto.beryl_curve_evp_pkey_free(libcrypto_key)
      end
      STDOUT.puts "curve Ed25519 on Wycheproof: #{cases_run} cases, the same verdict as libcrypto on each"
    end

    it "curve X25519 equals libcrypto on every Wycheproof case" do
      test_file = Wycheproof::TestFile(Wycheproof::KeyAgreementTestGroup).from_json(VectorFile.read("wycheproof/x25519_test.json"))
      cases_run = 0
      test_file.list_of_test_groups.each do |test_group|
        test_group.list_of_tests.each do |test|
          private_bytes = test.private_key.hexbytes
          peer = test.public_key.hexbytes
          beryl_shared = Beryl::Crypto::V1::X25519::PrivateKey.new(private_bytes).shared_secret(Beryl::Crypto::V1::X25519::PublicKey.new(peer))
          libcrypto_shared = LibcryptoCurveDifferential.libcrypto_x25519(private_bytes, peer)
          fail "x25519_test.json tcId #{test.test_case_id} (#{test.comment}) differs from libcrypto" unless beryl_shared == libcrypto_shared
          cases_run += 1
        end
      end
      STDOUT.puts "curve X25519 on Wycheproof: #{cases_run} cases, the same result as libcrypto on each"
    end

    it "curve P-256 ECDH equals libcrypto on random key pairs and altered points" do
      case_count = LibcryptoCurveDifferential.case_count(200_000)
      LibcryptoDifferential.describe_run("curve P-256 ECDH", case_count)
      settings = LibcryptoDifferential.settings
      refused = 0
      (settings.first_case...(settings.first_case + case_count)).each do |case_number|
        generator = LibcryptoDifferential.generator_for(103, case_number)
        own_key = LibcryptoCurveDifferential.generate_ec_key("prime256v1")
        peer_key = LibcryptoCurveDifferential.generate_ec_key("prime256v1")
        begin
          private_key = Beryl::Crypto::V1::P256::PrivateKey.new(LibcryptoCurveDifferential.ec_private_scalar(own_key, 32))
          own_point = LibcryptoCurveDifferential.ec_public_point(own_key)
          LibcryptoDifferential.report_mismatch("curve P-256 ECDH", case_number, "public key") unless private_key.public_key.to_uncompressed == own_point

          peer_point = LibcryptoCurveDifferential.ec_public_point(peer_key)
          # One case in four sends an altered point: a flipped bit, or the
          # compressed form.
          case generator.rand(8)
          when 0
            peer_point[1 + generator.rand(64)] ^= (1_u8 << generator.rand(8))
          when 1
            peer_point = Beryl::Crypto::V1::P256::PublicKey.new(peer_point).to_compressed
          end
          beryl_shared = begin
            private_key.shared_secret(Beryl::Crypto::V1::P256::PublicKey.new(peer_point))
          rescue Beryl::Crypto::InvalidPublicKey
            nil
          end
          libcrypto_peer = LibcryptoCurveDifferential.ec_public_key("prime256v1", peer_point)
          libcrypto_shared = libcrypto_peer ? LibcryptoCurveDifferential.derive(own_key, libcrypto_peer, validate_peer: 1) : nil
          LibCrypto.beryl_curve_evp_pkey_free(libcrypto_peer) if libcrypto_peer
          refused += 1 if beryl_shared.nil?
          unless beryl_shared == libcrypto_shared
            LibcryptoDifferential.report_mismatch("curve P-256 ECDH", case_number,
              "shared secret #{beryl_shared.try(&.hexstring)} vs #{libcrypto_shared.try(&.hexstring)} for #{peer_point.hexstring}")
          end
        ensure
          LibCrypto.beryl_curve_evp_pkey_free(own_key)
          LibCrypto.beryl_curve_evp_pkey_free(peer_key)
        end
      end
      STDOUT.puts "curve P-256 ECDH: #{case_count} cases, 0 mismatches (#{refused} altered points refused by both)"
    end

    {% for curve in [{"P-256", "P256", "prime256v1", 32, "SHA256"}, {"P-384", "P384", "secp384r1", 48, "SHA384"}] %}
      it "curve {{ curve[0].id }} ECDSA equals libcrypto on signatures and verdicts" do
        case_count = LibcryptoCurveDifferential.case_count(200_000)
        LibcryptoDifferential.describe_run("curve {{ curve[0].id }} ECDSA", case_count)
        settings = LibcryptoDifferential.settings
        digest = LibcryptoDifferential.libcrypto_digest({{ curve[4] }})
        altered_accepted = 0
        hybrid_points = 0
        (settings.first_case...(settings.first_case + case_count)).each do |case_number|
          generator = LibcryptoDifferential.generator_for({{ curve[3] }}, case_number)
          message = LibcryptoCurveDifferential.random_bytes(generator, generator.rand(0..LibcryptoCurveDifferential::LARGEST_MESSAGE))
          libcrypto_key = LibcryptoCurveDifferential.generate_ec_key({{ curve[2] }})
          begin
            point = LibcryptoCurveDifferential.ec_public_point(libcrypto_key)
            public_key = Beryl::Crypto::V1::{{ curve[1].id }}::PublicKey.new(point)
            libcrypto_signature = LibcryptoCurveDifferential.libcrypto_sign(libcrypto_key, digest.as(Void*), message)
            LibcryptoDifferential.report_mismatch("curve {{ curve[0].id }} ECDSA", case_number, "Beryl refused libcrypto's signature") unless public_key.verify(message, libcrypto_signature)
            signature = libcrypto_signature
            {% if curve[1] == "P256" %}
              private_key = Beryl::Crypto::V1::P256::PrivateKey.new(LibcryptoCurveDifferential.ec_private_scalar(libcrypto_key, 32))
              signature = private_key.sign(message)
              unless LibcryptoCurveDifferential.libcrypto_verify(libcrypto_key, digest.as(Void*), message, signature)
                LibcryptoDifferential.report_mismatch("curve P-256 ECDSA", case_number, "libcrypto refused Beryl's signature #{signature.hexstring}")
              end
            {% end %}

            altered_signature, altered_message, altered_point = LibcryptoCurveDifferential.alter(generator, signature, message, point, nil)
            beryl_verdict = LibcryptoCurveDifferential.beryl_ecdsa_verdict(altered_point, altered_message, altered_signature) do |encoded|
              Beryl::Crypto::V1::{{ curve[1].id }}::PublicKey.new(encoded)
            end
            if LibcryptoCurveDifferential.hybrid_point?(altered_point)
              # X9.62's hybrid form, which libcrypto reads and RFC 5480 §2.2
              # forbids. Beryl must refuse it; libcrypto's verdict must then
              # be Beryl's on the same point written uncompressed, when the
              # prefix states the parity of y correctly, and false when not.
              if beryl_verdict
                LibcryptoDifferential.report_mismatch("curve {{ curve[0].id }} ECDSA", case_number, "Beryl accepted the hybrid point #{altered_point.hexstring}")
              end
              hybrid_points += 1
              uncompressed = altered_point.dup
              uncompressed[0] = 0x04_u8
              beryl_verdict = altered_point[0] & 1 == altered_point[-1] & 1 &&
                              LibcryptoCurveDifferential.beryl_ecdsa_verdict(uncompressed, altered_message, altered_signature) do |encoded|
                                Beryl::Crypto::V1::{{ curve[1].id }}::PublicKey.new(encoded)
                              end
            end
            libcrypto_altered_key = LibcryptoCurveDifferential.ec_public_key({{ curve[2] }}, altered_point)
            libcrypto_verdict = libcrypto_altered_key ? LibcryptoCurveDifferential.libcrypto_verify(libcrypto_altered_key, digest.as(Void*), altered_message, altered_signature) : false
            LibCrypto.beryl_curve_evp_pkey_free(libcrypto_altered_key) if libcrypto_altered_key
            altered_accepted += 1 if beryl_verdict
            unless beryl_verdict == libcrypto_verdict
              LibcryptoDifferential.report_mismatch("curve {{ curve[0].id }} ECDSA", case_number,
                "altered case: Beryl #{beryl_verdict}, libcrypto #{libcrypto_verdict} (point #{altered_point.hexstring}, signature #{altered_signature.hexstring})")
            end
          ensure
            LibCrypto.beryl_curve_evp_pkey_free(libcrypto_key)
          end
        end
        STDOUT.puts "curve {{ curve[0].id }} ECDSA: #{case_count} cases and #{case_count} altered cases, 0 mismatches " \
                    "(#{altered_accepted} altered cases accepted by both; #{hybrid_points} hybrid points, refused by Beryl, judged in uncompressed form)"
      end
    {% end %}
  end
end
