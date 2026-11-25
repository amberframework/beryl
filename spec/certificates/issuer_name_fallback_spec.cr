require "../spec_helper"
require "../support/tls_harness"

# A private certificate authority, of the kind a PostgreSQL or MySQL server
# is often set up with, whose intermediate and leaf carry no authority key
# identifier. Beryl finds each issuer by name and verifies its signature, as
# Go's crypto/x509 and OpenSSL do.
private module PrivateAuthorityWithoutAuthorityKeyIdentifiers
  alias Certificates = Beryl::Certificates
  alias V1 = Beryl::Crypto::V1

  BASIC_CONSTRAINTS        = "2.5.29.19"
  KEY_USAGE                = "2.5.29.15"
  EXTENDED_KEY_USAGE       = "2.5.29.37"
  SUBJECT_KEY_IDENTIFIER   = "2.5.29.14"
  AUTHORITY_KEY_IDENTIFIER = "2.5.29.35"
  SUBJECT_ALTERNATIVE_NAME = "2.5.29.17"

  # An intermediate named *subject_name*, issued under *issuer_name* and signed with
  # *issuer_key*, with no authority key identifier.
  def self.intermediate(issuer_name : String, issuer_key : V1::P256::PrivateKey, *,
                        subject_name : String = "Database Intermediate CA") : {Certificates::Certificate, V1::P256::PrivateKey}
    key = V1::P256::PrivateKey.generate
    extensions = [
      TestCertificateAuthority.extension(BASIC_CONSTRAINTS, true, DerWriter.sequence(DerWriter.element(0x01_u8, Bytes[0xFF]))),
      TestCertificateAuthority.extension(KEY_USAGE, true, DerWriter.element(0x03_u8, Bytes[1, 0x06])),
      TestCertificateAuthority.extension(SUBJECT_KEY_IDENTIFIER, false,
        DerWriter.octet_string(TestCertificateAuthority.key_identifier(key.public_key.to_uncompressed))),
    ]
    certificate = TestCertificateAuthority.build(
      issuer_name: issuer_name, subject_name: subject_name,
      subject_public_key_info: TestCertificateAuthority.p256_public_key_info(key.public_key),
      extensions: extensions, not_before: Time.utc - 1.day, not_after: Time.utc + 365.days, signer: issuer_key)
    {certificate, key}
  end

  # A server leaf for localhost issued under *issuer_name* and signed with
  # *issuer_key*. It carries an authority key identifier only when
  # *authority_key_identifier* is given.
  def self.leaf(issuer_name : String, issuer_key : V1::P256::PrivateKey, *,
                authority_key_identifier : Bytes? = nil) : {Certificates::Certificate, V1::P256::PrivateKey}
    key = V1::P256::PrivateKey.generate
    extensions = [
      TestCertificateAuthority.extension(BASIC_CONSTRAINTS, true, DerWriter.element(0x30_u8, Bytes.empty)),
      TestCertificateAuthority.extension(KEY_USAGE, true, DerWriter.element(0x03_u8, Bytes[7, 0x80])),
      TestCertificateAuthority.extension(EXTENDED_KEY_USAGE, false, DerWriter.sequence(DerWriter.object_identifier("1.3.6.1.5.5.7.3.1"))),
      TestCertificateAuthority.extension(SUBJECT_ALTERNATIVE_NAME, false,
        DerWriter.element(0x30_u8, DerWriter.element(0x82_u8, "localhost".to_slice))),
    ]
    if authority_key_identifier
      extensions << TestCertificateAuthority.extension(AUTHORITY_KEY_IDENTIFIER, false,
        DerWriter.sequence(DerWriter.element(0x80_u8, authority_key_identifier)))
    end
    certificate = TestCertificateAuthority.build(
      issuer_name: issuer_name, subject_name: "localhost",
      subject_public_key_info: TestCertificateAuthority.p256_public_key_info(key.public_key),
      extensions: extensions, not_before: Time.utc - 1.day, not_after: Time.utc + 30.days, signer: issuer_key)
    {certificate, key}
  end

  def self.verification(list_of_anchors : Array(Certificates::Certificate), limits = Certificates::ChainVerification::Limits.new) : Certificates::ChainVerification
    Certificates::ChainVerification.new(Certificates::TrustStore.new(list_of_anchors), limits: limits)
  end
end

private alias Fixture = PrivateAuthorityWithoutAuthorityKeyIdentifiers

describe Beryl::Certificates::ChainVerification do
  describe "#verify, with no authority key identifier below the anchor" do
    it "verifies a private-CA chain whose intermediate and leaf omit the authority key identifier" do
      root = TestCertificateAuthority::Authority.new("Database Root CA")
      intermediate, intermediate_key = Fixture.intermediate("Database Root CA", root.private_key)
      leaf, _ = Fixture.leaf("Database Intermediate CA", intermediate_key)
      intermediate.authority_key_identifier.should be_nil
      leaf.authority_key_identifier.should be_nil

      path = Fixture.verification([root.certificate]).verify(leaf, [intermediate],
        identity: Beryl::Certificates::ServiceIdentity.new("localhost"))

      path.should eq([leaf, intermediate, root.certificate])
    end

    it "verifies a leaf without an authority key identifier issued straight by the anchor" do
      root = TestCertificateAuthority::Authority.new("Database Root CA")
      leaf, _ = Fixture.leaf("Database Root CA", root.private_key)

      Fixture.verification([root.certificate]).verify(leaf).should eq([leaf, root.certificate])
    end

    it "picks, among anchors of the same name, the one whose key signed the leaf" do
      decoy = TestCertificateAuthority::Authority.new("Database Root CA")
      root = TestCertificateAuthority::Authority.new("Database Root CA")
      leaf, _ = Fixture.leaf("Database Root CA", root.private_key)

      Fixture.verification([decoy.certificate, root.certificate]).verify(leaf).should eq([leaf, root.certificate])
    end

    it "picks, among intermediates of the same name, the one whose key signed the leaf" do
      root = TestCertificateAuthority::Authority.new("Database Root CA")
      decoy, _ = Fixture.intermediate("Database Root CA", root.private_key)
      intermediate, intermediate_key = Fixture.intermediate("Database Root CA", root.private_key)
      leaf, _ = Fixture.leaf("Database Intermediate CA", intermediate_key)

      path = Fixture.verification([root.certificate]).verify(leaf, [decoy, intermediate])

      path.should eq([leaf, intermediate, root.certificate])
    end

    it "refuses a leaf whose named issuer did not sign it" do
      root = TestCertificateAuthority::Authority.new("Database Root CA")
      impostor = TestCertificateAuthority::Authority.new("Database Root CA")
      leaf, _ = Fixture.leaf("Database Root CA", impostor.private_key)

      error = expect_raises(Beryl::Certificates::VerificationFailed) do
        Fixture.verification([root.certificate]).verify(leaf)
      end
      error.reason.should eq(Beryl::Certificates::FailureReason::NoTrustedPath)
    end

    it "keeps the signature-count limit when many same-named intermediates offer no key identifier to sort by" do
      root = TestCertificateAuthority::Authority.new("Database Root CA")
      list_of_decoys = Array.new(6) { Fixture.intermediate("Database Root CA", root.private_key)[0] }
      _, intermediate_key = Fixture.intermediate("Database Root CA", root.private_key)
      leaf, _ = Fixture.leaf("Database Intermediate CA", intermediate_key)
      limits = Beryl::Certificates::ChainVerification::Limits.new(largest_signature_check_count: 3)

      error = expect_raises(Beryl::Certificates::VerificationFailed) do
        Fixture.verification([root.certificate], limits).verify(leaf, list_of_decoys)
      end
      error.reason.should eq(Beryl::Certificates::FailureReason::BudgetExceeded)
    end

    it "still tries the candidate whose subject key identifier matches first when the leaf has one" do
      root = TestCertificateAuthority::Authority.new("Database Root CA")
      list_of_decoys = Array.new(6) { Fixture.intermediate("Database Root CA", root.private_key)[0] }
      intermediate, intermediate_key = Fixture.intermediate("Database Root CA", root.private_key)
      key_identifier = TestCertificateAuthority.key_identifier(intermediate_key.public_key.to_uncompressed)
      leaf, _ = Fixture.leaf("Database Intermediate CA", intermediate_key, authority_key_identifier: key_identifier)
      limits = Beryl::Certificates::ChainVerification::Limits.new(largest_signature_check_count: 3)

      path = Fixture.verification([root.certificate], limits).verify(leaf, list_of_decoys + [intermediate])

      path.should eq([leaf, intermediate, root.certificate])
    end
  end
end

describe Beryl::TLS::Socket::Client do
  it "completes a TLS 1.3 handshake with a server whose private-CA chain omits authority key identifiers" do
    root = TestCertificateAuthority::Authority.new("Database Root CA")
    intermediate, intermediate_key = Fixture.intermediate("Database Root CA", root.private_key)
    leaf, leaf_key = Fixture.leaf("Database Intermediate CA", intermediate_key)
    server_context = Beryl::TLS::Context::Server.new
    server_context.certified_key = Beryl::TLS::CertifiedKey.new([leaf, intermediate], leaf_key)
    client_context = Beryl::TLS::Context::Client.new
    client_context.trust_store = root.trust_store

    TlsHarness.connect(server_context, client_context) do |client, server|
      client.should be_a(Beryl::TLS::Socket::Client)
      server.should be_a(Beryl::TLS::Socket::Server)
    end
  end
end
