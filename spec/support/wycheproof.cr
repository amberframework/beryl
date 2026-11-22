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
