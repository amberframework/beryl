require "json"

# The x509-limbo test suite (C2SP/x509-limbo, `limbo.json`) as typed
# structures. Field names follow `limbo-schema.json`.
module X509Limbo
  struct PeerName
    include JSON::Serializable

    getter kind : String = ""
    getter value : String = ""
  end

  struct Testcase
    include JSON::Serializable

    getter id : String = ""
    getter description : String = ""
    @[JSON::Field(key: "conflicts_with")]
    getter conflicts_with : Array(String) = [] of String
    getter features : Array(String) = [] of String
    getter validation_kind : String = ""
    getter trusted_certs : Array(String) = [] of String
    getter untrusted_intermediates : Array(String) = [] of String
    getter peer_certificate : String = ""
    getter validation_time : String? = nil
    getter key_usage : Array(String) = [] of String
    getter extended_key_usage : Array(String) = [] of String
    getter expected_result : String = ""
    getter expected_peer_name : PeerName? = nil
    getter max_chain_depth : Int32? = nil
    getter crls : Array(String) = [] of String
  end

  struct Suite
    include JSON::Serializable

    getter version : Int32 = 0
    getter testcases : Array(Testcase) = [] of Testcase
  end
end
