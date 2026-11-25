require "../spec_helper"

# Two chains signed with SHA-1, made once by scripts/generate_sha1_signed_chains.sh
# (OpenSSL pinned by version and sha256) and pinned in spec/vectors/manifest.json:
# an RSA leaf signed with sha1WithRSAEncryption, and an ECDSA intermediate
# signed with ecdsa-with-SHA1. Beryl refuses both by the algorithm
# identifier, before checking the signature, with a message that names
# SHA-1 (RFC 9155).
private module SHA1SignedChains
  alias Certificates = Beryl::Certificates

  # Inside every certificate's validity (2026-01-01 to 2046-01-01).
  VALIDATION_TIME = Time.utc(2030, 1, 1)

  class_getter list_of_certificates : Array(Certificates::Certificate) do
    pem_text = VectorFile.read("beryl/sha1_signed_chains.pem")
    Beryl::Encoding::PEM.decode(pem_text, label: "CERTIFICATE").map { |der| Certificates::Certificate.new(der) }
  end

  def self.rsa_root : Certificates::Certificate
    list_of_certificates[0]
  end

  def self.rsa_leaf : Certificates::Certificate
    list_of_certificates[1]
  end

  def self.ec_root : Certificates::Certificate
    list_of_certificates[2]
  end

  def self.ec_intermediate : Certificates::Certificate
    list_of_certificates[3]
  end

  def self.ec_leaf : Certificates::Certificate
    list_of_certificates[4]
  end
end

private def verification_failure(trust_anchor : Beryl::Certificates::Certificate, leaf : Beryl::Certificates::Certificate,
                                 list_of_intermediates : Array(Beryl::Certificates::Certificate), dns_name : String) : Beryl::Certificates::VerificationFailed
  verification = Beryl::Certificates::ChainVerification.new(Beryl::Certificates::TrustStore.new([trust_anchor]))
  expect_raises(Beryl::Certificates::VerificationFailed) do
    verification.verify(leaf, list_of_intermediates,
      identity: Beryl::Certificates::ServiceIdentity.new(dns_name), time: SHA1SignedChains::VALIDATION_TIME)
  end
end

describe "SHA-1 certificate signatures" do
  describe "the fixture" do
    it "holds real SHA-1 signatures, checked with SHA-1 outside the verifier" do
      rsa_key = SHA1SignedChains.rsa_root.subject_public_key_info.verification_key
      if rsa_key.is_a?(Beryl::Crypto::V1::RSA::PublicKey)
        rsa_key.verify_pkcs1_signature(SHA1SignedChains.rsa_leaf.to_be_signed, SHA1SignedChains.rsa_leaf.signature,
          hash_function: Beryl::Crypto::Compatibility::SHA1).should be_true
      else
        fail "the RSA root has no RSA key"
      end

      ec_key = SHA1SignedChains.ec_root.subject_public_key_info.verification_key
      if ec_key.is_a?(Beryl::Crypto::V1::P256::PublicKey)
        digest = Beryl::Crypto::Compatibility::SHA1.digest(SHA1SignedChains.ec_intermediate.to_be_signed)
        ec_key.verify_digest(digest, SHA1SignedChains.ec_intermediate.signature).should be_true
      else
        fail "the EC root has no P-256 key"
      end
    end
  end

  describe Beryl::Certificates::ChainVerification do
    it "refuses a leaf signed with sha1WithRSAEncryption, naming SHA-1" do
      failure = verification_failure(SHA1SignedChains.rsa_root, SHA1SignedChains.rsa_leaf, [] of Beryl::Certificates::Certificate,
        "sha1-rsa.beryl.test")
      failure.reason.should eq(Beryl::Certificates::FailureReason::SignatureAlgorithmRefused)
      failure.message.should eq("the certificate for CN=sha1-rsa.beryl.test is signed with SHA-1, which Beryl refuses (RFC 9155)")
    end

    it "refuses an intermediate signed with ecdsa-with-SHA1, naming SHA-1" do
      failure = verification_failure(SHA1SignedChains.ec_root, SHA1SignedChains.ec_leaf, [SHA1SignedChains.ec_intermediate],
        "sha1-ec.beryl.test")
      failure.reason.should eq(Beryl::Certificates::FailureReason::SignatureAlgorithmRefused)
      failure.message.should eq("the certificate for CN=Beryl SHA-1 Test EC Intermediate is signed with SHA-1, which Beryl refuses (RFC 9155)")
    end
  end

  describe Beryl::Certificates::SignatureAlgorithm do
    it "names the hash of every SHA-1 and MD5 signature algorithm, and of no other" do
      {
        "1.2.840.113549.1.1.5"  => "SHA-1",
        "1.3.14.3.2.29"         => "SHA-1",
        "1.2.840.10045.4.1"     => "SHA-1",
        "1.2.840.10040.4.3"     => "SHA-1",
        "1.2.840.113549.1.1.4"  => "MD5",
        "1.2.840.113549.1.1.11" => nil,
        "1.2.840.10045.4.3.2"   => nil,
        "1.3.101.112"           => nil,
      }.each do |dotted, expected|
        reader = Beryl::Encoding::DER::Reader.new(DerWriter.sequence(DerWriter.object_identifier(dotted)))
        Beryl::Certificates::SignatureAlgorithm.read(reader).refused_hash_function_name.should eq(expected), failure_message: dotted
      end
    end
  end

  describe Beryl::TLS::WebPkiVerifier do
    it "rejects the chain with the bad_certificate alert and a message naming SHA-1" do
      verifier = Beryl::TLS::WebPkiVerifier.new(Beryl::Certificates::TrustStore.new([SHA1SignedChains.rsa_root]),
        time_source: -> { SHA1SignedChains::VALIDATION_TIME })
      error = expect_raises(Beryl::TLS::CertificateRejected) do
        verifier.verify_chain([SHA1SignedChains.rsa_leaf], "sha1-rsa.beryl.test")
      end
      error.alert_description.should eq(Beryl::TLS::AlertDescription::BadCertificate)
      error.message.should eq("the certificate chain did not verify: the certificate for CN=sha1-rsa.beryl.test is signed with SHA-1, which Beryl refuses (RFC 9155)")
    end
  end

  describe Beryl::TLS::CertificateVerifier do
    it "refuses a SHA-1 CertificateVerify scheme before checking the signature, naming SHA-1" do
      key = SHA1SignedChains.rsa_leaf.subject_public_key_info.verification_key || fail "the RSA leaf has no key"
      {Beryl::TLS::SignatureScheme::RsaPkcs1Sha1, Beryl::TLS::SignatureScheme::EcdsaSha1}.each do |scheme|
        error = expect_raises(Beryl::TLS::Error, "is signed with SHA-1") do
          Beryl::TLS::CertificateVerifier.verify_with_key(key, scheme, "content".to_slice, Bytes.new(256))
        end
        error.alert_description.should eq(Beryl::TLS::AlertDescription::IllegalParameter)
      end
    end
  end
end
