require "json"

# The Wycheproof test vector files (`testvectors_v1`) this suite reads, as
# typed structures. Field names follow the files' schemas
# (`mac_test_schema_v1.json`, `hkdf_test_schema_v1.json`,
# `pbkdf_test_schema.json`).
module Wycheproof
  struct TestFile(G)
    include JSON::Serializable

    getter algorithm : String = ""

    @[JSON::Field(key: "numberOfTests")]
    getter number_of_tests : Int32 = 0

    @[JSON::Field(key: "testGroups")]
    getter list_of_test_groups : Array(G) = [] of G
  end

  struct MacTest
    include JSON::Serializable

    @[JSON::Field(key: "tcId")]
    getter test_case_id : Int32 = 0
    getter comment : String = ""
    getter key : String = ""
    @[JSON::Field(key: "msg")]
    getter message : String = ""
    getter tag : String = ""
    getter result : String = ""
  end

  struct MacTestGroup
    include JSON::Serializable

    @[JSON::Field(key: "keySize")]
    getter key_bit_size : Int32 = 0
    @[JSON::Field(key: "tagSize")]
    getter tag_bit_size : Int32 = 0
    @[JSON::Field(key: "tests")]
    getter list_of_tests : Array(MacTest) = [] of MacTest
  end

  struct HkdfTest
    include JSON::Serializable

    @[JSON::Field(key: "tcId")]
    getter test_case_id : Int32 = 0
    getter comment : String = ""
    @[JSON::Field(key: "ikm")]
    getter input_key_material : String = ""
    getter salt : String = ""
    getter info : String = ""
    @[JSON::Field(key: "size")]
    getter derived_key_bytesize : Int32 = 0
    @[JSON::Field(key: "okm")]
    getter derived_key : String = ""
    getter result : String = ""
  end

  struct HkdfTestGroup
    include JSON::Serializable

    @[JSON::Field(key: "tests")]
    getter list_of_tests : Array(HkdfTest) = [] of HkdfTest
  end

  struct PbkdfTest
    include JSON::Serializable

    @[JSON::Field(key: "tcId")]
    getter test_case_id : Int32 = 0
    getter comment : String = ""
    getter password : String = ""
    getter salt : String = ""
    @[JSON::Field(key: "iterationCount")]
    getter iteration_count : Int32 = 0
    @[JSON::Field(key: "dkLen")]
    getter derived_key_bytesize : Int32 = 0
    @[JSON::Field(key: "dk")]
    getter derived_key : String = ""
    getter result : String = ""
  end

  struct PbkdfTestGroup
    include JSON::Serializable

    @[JSON::Field(key: "tests")]
    getter list_of_tests : Array(PbkdfTest) = [] of PbkdfTest
  end
end

# The cipher files (`aead_test_schema_v1.json`, `ind_cpa_test_schema_v1.json`).
module Wycheproof
  struct AeadTest
    include JSON::Serializable

    @[JSON::Field(key: "tcId")]
    getter test_case_id : Int32 = 0
    getter comment : String = ""
    getter key : String = ""
    @[JSON::Field(key: "iv")]
    getter nonce : String = ""
    @[JSON::Field(key: "aad")]
    getter associated_data : String = ""
    @[JSON::Field(key: "msg")]
    getter message : String = ""
    @[JSON::Field(key: "ct")]
    getter ciphertext : String = ""
    getter tag : String = ""
    getter result : String = ""
  end

  struct AeadTestGroup
    include JSON::Serializable

    @[JSON::Field(key: "ivSize")]
    getter nonce_bit_size : Int32 = 0
    @[JSON::Field(key: "keySize")]
    getter key_bit_size : Int32 = 0
    @[JSON::Field(key: "tagSize")]
    getter tag_bit_size : Int32 = 0
    @[JSON::Field(key: "tests")]
    getter list_of_tests : Array(AeadTest) = [] of AeadTest
  end

  struct BlockCipherModeTest
    include JSON::Serializable

    @[JSON::Field(key: "tcId")]
    getter test_case_id : Int32 = 0
    getter comment : String = ""
    getter key : String = ""
    @[JSON::Field(key: "iv")]
    getter initialization_vector : String = ""
    @[JSON::Field(key: "msg")]
    getter message : String = ""
    @[JSON::Field(key: "ct")]
    getter ciphertext : String = ""
    getter result : String = ""
  end

  struct BlockCipherModeTestGroup
    include JSON::Serializable

    @[JSON::Field(key: "keySize")]
    getter key_bit_size : Int32 = 0
    @[JSON::Field(key: "tests")]
    getter list_of_tests : Array(BlockCipherModeTest) = [] of BlockCipherModeTest
  end
end

# The public-key files (`xdh_comp_schema_v1.json`, `eddsa_verify_schema_v1.json`,
# `ecdh_ecpoint_test_schema_v1.json`, `ecdsa_verify_schema_v1.json`,
# `ecdsa_p1363_verify_schema_v1.json`).
module Wycheproof
  struct KeyAgreementTest
    include JSON::Serializable

    @[JSON::Field(key: "tcId")]
    getter test_case_id : Int32 = 0
    getter comment : String = ""
    getter flags : Array(String) = [] of String
    @[JSON::Field(key: "public")]
    getter public_key : String = ""
    @[JSON::Field(key: "private")]
    getter private_key : String = ""
    getter shared : String = ""
    getter result : String = ""
  end

  struct KeyAgreementTestGroup
    include JSON::Serializable

    getter curve : String = ""
    @[JSON::Field(key: "tests")]
    getter list_of_tests : Array(KeyAgreementTest) = [] of KeyAgreementTest
  end

  struct SignatureTest
    include JSON::Serializable

    @[JSON::Field(key: "tcId")]
    getter test_case_id : Int32 = 0
    getter comment : String = ""
    getter flags : Array(String) = [] of String
    @[JSON::Field(key: "msg")]
    getter message : String = ""
    @[JSON::Field(key: "sig")]
    getter signature : String = ""
    getter result : String = ""
  end

  struct EddsaPublicKey
    include JSON::Serializable

    @[JSON::Field(key: "pk")]
    getter encoded : String = ""
  end

  struct EddsaVerifyTestGroup
    include JSON::Serializable

    @[JSON::Field(key: "publicKeyDer")]
    getter public_key_der : String = ""

    @[JSON::Field(key: "publicKey")]
    getter public_key : EddsaPublicKey = EddsaPublicKey.from_json("{}")
    @[JSON::Field(key: "tests")]
    getter list_of_tests : Array(SignatureTest) = [] of SignatureTest
  end

  struct EcPublicKey
    include JSON::Serializable

    getter curve : String = ""
    getter uncompressed : String = ""
  end

  struct EcdsaVerifyTestGroup
    include JSON::Serializable

    @[JSON::Field(key: "publicKeyDer")]
    getter public_key_der : String = ""

    @[JSON::Field(key: "publicKey")]
    getter public_key : EcPublicKey = EcPublicKey.from_json("{}")
    @[JSON::Field(key: "sha")]
    getter hash_name : String = ""
    @[JSON::Field(key: "tests")]
    getter list_of_tests : Array(SignatureTest) = [] of SignatureTest
  end
end

# The RSA files (`rsassa_pkcs1_verify_schema_v1.json`,
# `rsassa_pkcs1_generate_schema_v1.json`, `rsassa_pss_verify_schema_v1.json`,
# `rsaes_oaep_decrypt_schema_v1.json`). A component a file does not carry
# reads as the empty string.
module Wycheproof
  struct RsaKey
    include JSON::Serializable

    getter modulus : String = ""
    @[JSON::Field(key: "publicExponent")]
    getter public_exponent : String = ""
    @[JSON::Field(key: "privateExponent")]
    getter private_exponent : String = ""
    @[JSON::Field(key: "prime1")]
    getter first_prime : String = ""
    @[JSON::Field(key: "prime2")]
    getter second_prime : String = ""
    @[JSON::Field(key: "exponent1")]
    getter first_prime_exponent : String = ""
    @[JSON::Field(key: "exponent2")]
    getter second_prime_exponent : String = ""
    getter coefficient : String = ""
  end

  struct RsaSignatureTest
    include JSON::Serializable

    @[JSON::Field(key: "tcId")]
    getter test_case_id : Int32 = 0
    getter comment : String = ""
    @[JSON::Field(key: "msg")]
    getter message : String = ""
    @[JSON::Field(key: "sig")]
    getter signature : String = ""
    getter result : String = ""
    @[JSON::Field(key: "flags")]
    getter list_of_flags : Array(String) = [] of String
  end

  struct RsaSignatureTestGroup
    include JSON::Serializable

    @[JSON::Field(key: "publicKeyDer")]
    getter public_key_der : String = ""

    @[JSON::Field(key: "keySize")]
    getter key_bit_size : Int32 = 0
    @[JSON::Field(key: "sha")]
    getter hash_name : String = ""
    @[JSON::Field(key: "mgfSha")]
    getter mask_generation_hash_name : String = ""
    @[JSON::Field(key: "sLen")]
    getter salt_bytesize : Int32 = 0
    @[JSON::Field(key: "publicKey")]
    getter public_key : RsaKey = RsaKey.from_json("{}")
    @[JSON::Field(key: "privateKey")]
    getter private_key : RsaKey = RsaKey.from_json("{}")
    @[JSON::Field(key: "tests")]
    getter list_of_tests : Array(RsaSignatureTest) = [] of RsaSignatureTest
  end

  struct RsaOaepTest
    include JSON::Serializable

    @[JSON::Field(key: "tcId")]
    getter test_case_id : Int32 = 0
    getter comment : String = ""
    @[JSON::Field(key: "msg")]
    getter message : String = ""
    @[JSON::Field(key: "ct")]
    getter ciphertext : String = ""
    getter label : String = ""
    getter result : String = ""
    @[JSON::Field(key: "flags")]
    getter list_of_flags : Array(String) = [] of String
  end

  struct RsaOaepTestGroup
    include JSON::Serializable

    @[JSON::Field(key: "keySize")]
    getter key_bit_size : Int32 = 0
    @[JSON::Field(key: "sha")]
    getter hash_name : String = ""
    @[JSON::Field(key: "mgfSha")]
    getter mask_generation_hash_name : String = ""
    @[JSON::Field(key: "privateKey")]
    getter private_key : RsaKey = RsaKey.from_json("{}")
    @[JSON::Field(key: "tests")]
    getter list_of_tests : Array(RsaOaepTest) = [] of RsaOaepTest
  end
end
