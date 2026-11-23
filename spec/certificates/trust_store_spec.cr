require "../spec_helper"
require "digest/sha256"

describe Beryl::Certificates::TrustStore do
  it "compiles in the Mozilla root set it pins" do
    Digest::SHA256.hexdigest(Beryl::Certificates::TrustStore::MOZILLA_ROOTS_PEM).should eq(Beryl::Certificates::TrustStore::MOZILLA_ROOTS_SHA256)
  end

  it "compiles in the Public Suffix List it pins" do
    Digest::SHA256.hexdigest(Beryl::Certificates::PublicSuffixList::TEXT).should eq(Beryl::Certificates::PublicSuffixList::SHA256)
  end

  it "reads every Mozilla root, and every one is a usable trust anchor" do
    block_count = Beryl::Encoding::PEM.decode(Beryl::Certificates::TrustStore::MOZILLA_ROOTS_PEM, label: "CERTIFICATE").size
    store = Beryl::Certificates::TrustStore.mozilla
    store.size.should eq(block_count)
    list_of_violations = store.list_of_certificates.compact_map do |root|
      reason = Beryl::Certificates::ChainVerification.anchor_profile_violation(root)
      reason ? "#{root.subject}: #{reason}" : nil
    end
    # e-Szigno TLS Root CA 2023 has a P-521 key, a curve Beryl has not built.
    list_of_violations.size.should eq(1)
    list_of_violations.first.should contain("e-Szigno TLS Root CA 2023")
    list_of_violations.first.should contain("1.3.132.0.35")
  end

  it "reads the operating system's bundle when one is present" do
    path = Beryl::Certificates::TrustStore::LIST_OF_SYSTEM_BUNDLE_PATHS.find { |candidate| File.exists?(candidate) }
    if path
      Beryl::Certificates::TrustStore.system.size.should be > 50
    end
  end
end
