require "../spec_helper"

private def read_with(bytes : Bytes, &)
  reader = Beryl::Encoding::DER::Reader.new(bytes)
  yield reader
  reader.finish
end

describe Beryl::Encoding::DER do
  it "reads a sequence of an integer, a boolean and an object identifier" do
    bytes = DerWriter.sequence(DerWriter.small_integer(5), Bytes[0x01, 0x01, 0xff], DerWriter.object_identifier("1.2.840.113549.1.1.11"))
    read_with(bytes) do |reader|
      reader.read_sequence do |sequence|
        sequence.read_small_integer.should eq(5)
        sequence.read_boolean.should be_true
        sequence.read_object_identifier.to_s.should eq("1.2.840.113549.1.1.11")
      end
    end
  end

  {
    "an indefinite length"                   => Bytes[0x30, 0x80, 0x00, 0x00],
    "a long-form length under 128"           => Bytes[0x04, 0x81, 0x01, 0x00],
    "a length with a leading zero"           => Bytes[0x04, 0x82, 0x00, 0x81] + Bytes.new(0x81),
    "a length past the input"                => Bytes[0x04, 0x05, 0x00],
    "a non-minimal integer"                  => Bytes[0x02, 0x02, 0x00, 0x01],
    "a BOOLEAN that is neither 0 nor FF"     => Bytes[0x01, 0x01, 0x01],
    "a BIT STRING with unused bits set"      => Bytes[0x03, 0x02, 0x01, 0x01],
    "an OID arc with a leading zero group"   => Bytes[0x06, 0x02, 0x80, 0x01],
    "a tag number below 31 in the long form" => Bytes[0x1f, 0x05, 0x00],
  }.each do |description, bytes|
    it "refuses #{description}" do
      expect_raises(Beryl::Encoding::MalformedEncoding) do
        read_with(bytes) do |reader|
          element = reader.read_element
          case element.tag
          when Beryl::Encoding::DER::INTEGER           then Beryl::Encoding::DER.check_minimal_integer(element)
          when Beryl::Encoding::DER::BOOLEAN           then Beryl::Encoding::DER::Reader.new(element.encoded).read_boolean
          when Beryl::Encoding::DER::BIT_STRING        then Beryl::Encoding::DER.decode_bit_string(element)
          when Beryl::Encoding::DER::OBJECT_IDENTIFIER then Beryl::Encoding::DER.check_object_identifier(element)
          end
        end
      end
    end
  end

  it "refuses nesting deeper than its limit" do
    bytes = Bytes[0x04, 0x00]
    40.times { bytes = DerWriter.sequence(bytes) }
    expect_raises(Beryl::Encoding::LimitExceeded) do
      reader = Beryl::Encoding::DER::Reader.new(bytes)
      descend = uninitialized Proc(Beryl::Encoding::DER::Reader, Nil)
      descend = ->(current : Beryl::Encoding::DER::Reader) do
        if current.next_is?(Beryl::Encoding::DER::SEQUENCE)
          current.read_sequence { |inner| descend.call(inner) }
        else
          current.read_element
        end
        nil
      end
      descend.call(reader)
    end
  end

  it "refuses an input larger than its limit" do
    expect_raises(Beryl::Encoding::LimitExceeded) do
      Beryl::Encoding::DER::Reader.new(Bytes.new(100), Beryl::Encoding::DER::Limits.new(largest_input_bytesize: 99))
    end
  end

  it "reads both time forms and refuses others" do
    utc = Bytes[0x17, 13] + "491231235959Z".to_slice
    generalized = Bytes[0x18, 15] + "20500101000000Z".to_slice
    Beryl::Encoding::DER::Reader.new(utc).read_time.should eq(Time.utc(2049, 12, 31, 23, 59, 59))
    Beryl::Encoding::DER::Reader.new(generalized).read_time.should eq(Time.utc(2050, 1, 1))
    expect_raises(Beryl::Encoding::MalformedEncoding) { Beryl::Encoding::DER::Reader.new(Bytes[0x17, 11] + "4912312359Z".to_slice).read_time }
    expect_raises(Beryl::Encoding::MalformedEncoding) { Beryl::Encoding::DER::Reader.new(Bytes[0x18, 15] + "20500230000000Z".to_slice).read_time }
  end
end

describe Beryl::Encoding::PEM do
  it "reads blocks and ignores text around them" do
    text = "comment\n" + Beryl::Encoding::PEM.encode(Bytes[1, 2, 3], label: "CERTIFICATE") + "more\r\n" +
           Beryl::Encoding::PEM.encode(Bytes[4], label: "X509 CRL")
    Beryl::Encoding::PEM.decode(text, label: "CERTIFICATE").should eq([Bytes[1, 2, 3]])
    Beryl::Encoding::PEM.decode_blocks(text).map(&.label).should eq(["CERTIFICATE", "X509 CRL"])
  end

  it "refuses a block whose END label differs, or that never ends" do
    expect_raises(Beryl::Encoding::MalformedEncoding) { Beryl::Encoding::PEM.decode_blocks("-----BEGIN A-----\nAQID\n-----END B-----\n") }
    expect_raises(Beryl::Encoding::MalformedEncoding) { Beryl::Encoding::PEM.decode_blocks("-----BEGIN A-----\nAQID\n") }
    expect_raises(Beryl::Encoding::MalformedEncoding) { Beryl::Encoding::PEM.decode_blocks("-----BEGIN A-----\nAQ*D\n-----END A-----\n") }
  end
end

describe Beryl::Certificates::ServiceIdentity do
  it "matches DNS names as RFC 9525 §6.3 says" do
    {
      {"example.com", "example.com"}                 => true,
      {"EXAMPLE.com", "example.com."}                => true,
      {"*.example.com", "foo.example.com"}           => true,
      {"*.example.com", "a.b.example.com"}           => false,
      {"*.example.com", "example.com"}               => false,
      {"f*.example.com", "foo.example.com"}          => false,
      {"foo.*.example.com", "foo.bar.example.com"}   => false,
      {"*.com", "example.com"}                       => false,
      {"*.co.uk", "example.co.uk"}                   => false,
      {"*.s3.amazonaws.com", "x.s3.amazonaws.com"}   => false,
      {"foo_bar.example.com", "foo_bar.example.com"} => false,
    }.each do |(presented, reference), expected|
      identity = Beryl::Certificates::ServiceIdentity.new(reference)
      Beryl::Certificates::ServiceIdentity.domain_name_matches?(presented, identity.domain_name.not_nil!).should eq(expected)
    end
  end

  it "reads IP addresses and writes them in canonical form" do
    Beryl::Certificates::ServiceIdentity.new("192.0.2.1").ip_address.should eq(Bytes[192, 0, 2, 1])
    Beryl::Certificates::ServiceIdentity.parse_ip_address("192.168.001.001").should be_nil
    address = Beryl::Certificates::ServiceIdentity.parse_ip_address("2001:DB8:0:0:1:0:0:1").not_nil!
    Beryl::Certificates::ServiceIdentity.format_ip_address(address).should eq("2001:db8::1:0:0:1")
    Beryl::Certificates::ServiceIdentity.format_ip_address(Beryl::Certificates::ServiceIdentity.parse_ip_address("::ffff:192.0.2.1").not_nil!).should eq("::ffff:c000:201")
  end

  it "refuses a reference that is neither a name nor an address" do
    expect_raises(ArgumentError) { Beryl::Certificates::ServiceIdentity.new("bad name") }
    expect_raises(ArgumentError) { Beryl::Certificates::ServiceIdentity.new("ünicode.example") }
  end
end

describe Beryl::Certificates::PrivateKeyFile do
  it "reads a P-256 key from SEC 1 and from PKCS #8" do
    key = Beryl::Crypto::V1::P256::PrivateKey.generate
    scalar = key.to_slice
    sec1 = DerWriter.sequence(DerWriter.small_integer(1), DerWriter.octet_string(scalar),
      DerWriter.context(0, DerWriter.object_identifier("1.2.840.10045.3.1.7")))
    read = Beryl::Certificates::PrivateKeyFile.read_pem(Beryl::Encoding::PEM.encode(sec1, label: "EC PRIVATE KEY"))
    read.should be_a(Beryl::Crypto::V1::P256::PrivateKey)
    read.as(Beryl::Crypto::V1::P256::PrivateKey).public_key.should eq(key.public_key)

    inner = DerWriter.sequence(DerWriter.small_integer(1), DerWriter.octet_string(scalar))
    pkcs8 = DerWriter.sequence(DerWriter.small_integer(0),
      DerWriter.sequence(DerWriter.object_identifier("1.2.840.10045.2.1"), DerWriter.object_identifier("1.2.840.10045.3.1.7")),
      DerWriter.octet_string(inner))
    Beryl::Certificates::PrivateKeyFile.read_der(pkcs8).as(Beryl::Crypto::V1::P256::PrivateKey).public_key.should eq(key.public_key)
  end

  it "reads an Ed25519 key from PKCS #8 (RFC 8410 §7)" do
    seed = Random::Secure.random_bytes(32)
    pkcs8 = DerWriter.sequence(DerWriter.small_integer(0), DerWriter.sequence(DerWriter.object_identifier("1.3.101.112")),
      DerWriter.octet_string(DerWriter.octet_string(seed)))
    key = Beryl::Certificates::PrivateKeyFile.read_pem(Beryl::Encoding::PEM.encode(pkcs8, label: "PRIVATE KEY"))
    key.as(Beryl::Crypto::V1::Ed25519::SigningKey).verification_key.to_slice.should eq(Beryl::Crypto::V1::Ed25519::SigningKey.new(seed).verification_key.to_slice)
  end

  it "reads an RSA key from PKCS #1" do
    test_file = Wycheproof::TestFile(Wycheproof::RsaSignatureTestGroup).from_json(VectorFile.read("wycheproof/rsa_pkcs1_2048_sig_gen_test.json"))
    components = RsaKeyComponents.from_wycheproof(test_file.list_of_test_groups.first.private_key)
    der = DerWriter.sequence(DerWriter.small_integer(0), DerWriter.integer(components.modulus), DerWriter.integer(components.public_exponent),
      DerWriter.integer(components.private_exponent), DerWriter.integer(components.first_prime), DerWriter.integer(components.second_prime),
      DerWriter.integer(components.first_prime_exponent), DerWriter.integer(components.second_prime_exponent), DerWriter.integer(components.coefficient))
    key = Beryl::Certificates::PrivateKeyFile.read_pem(Beryl::Encoding::PEM.encode(der, label: "RSA PRIVATE KEY"))
    key.as(Beryl::Crypto::V1::RSA::PrivateKey).modulus_bit_count.should eq(2048)
  end

  it "refuses a key on a curve Beryl does not sign with" do
    sec1 = DerWriter.sequence(DerWriter.small_integer(1), DerWriter.octet_string(Bytes.new(48, 1_u8)),
      DerWriter.context(0, DerWriter.object_identifier("1.3.132.0.34")))
    expect_raises(Beryl::Certificates::UnsupportedKey) { Beryl::Certificates::PrivateKeyFile.read_elliptic_curve_der(sec1) }
  end
end

describe Beryl::Certificates do
  it "verifies a real chain against the Mozilla roots" do
    suite = X509Limbo::Suite.from_json(VectorFile.read("x509-limbo/limbo.json"))
    testcase = suite.testcases.find { |candidate| candidate.id == "online::google.com" }.not_nil!
    chain = Beryl::Certificates.read_pem_chain(testcase.peer_certificate + testcase.untrusted_intermediates.join)
    time = Time.parse_rfc3339(testcase.validation_time.not_nil!)
    path = Beryl::Certificates::ChainVerification.new(Beryl::Certificates::TrustStore.mozilla, limits: Beryl::Certificates::ChainVerification::Limits.new(largest_elapsed_time: 5.seconds))
      .verify(chain.first, chain[1..], identity: Beryl::Certificates::ServiceIdentity.new("google.com"), time: time)
    Beryl::Certificates::TrustStore.mozilla.includes?(path.last).should be_true
  end
end
