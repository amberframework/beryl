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

  describe ".system on macOS" do
    it "joins the pinned Mozilla roots to /etc/ssl/cert.pem, which trails the keychain" do
      {% if flag?(:darwin) %}
        with_ssl_cert_file("") do
          Beryl::Certificates::TrustStore.joins_mozilla_roots_to_the_system_bundle?.should be_true
          system = Beryl::Certificates::TrustStore.system
          bundle = Beryl::Certificates::TrustStore.from_pem(File.read(Beryl::Certificates::TrustStore.system_bundle_path))
          list_of_missing_mozilla_roots = Beryl::Certificates::TrustStore.mozilla.list_of_certificates.reject { |root| system.includes?(root) }
          list_of_missing_bundle_certificates = bundle.list_of_certificates.reject { |root| system.includes?(root) }
          list_of_missing_mozilla_roots.should be_empty
          list_of_missing_bundle_certificates.should be_empty
          # SSL.com TLS ECC Root CA 2022 ends the chain www.example.com
          # served in November 2026, and macOS 27.2.1's /etc/ssl/cert.pem
          # does not hold it.
          system.list_of_certificates.any?(&.subject.to_s.includes?("SSL.com TLS ECC Root CA 2022")).should be_true
        end
      {% else %}
        Beryl::Certificates::TrustStore.joins_mozilla_roots_to_the_system_bundle?.should be_false
      {% end %}
    end

    it "reads only the file SSL_CERT_FILE names, on macOS too" do
      bundle = File.tempname("beryl-ssl-cert-file", ".pem")
      File.write(bundle, Beryl::Certificates::TrustStore.mozilla.list_of_certificates.first.to_pem)
      with_ssl_cert_file(bundle) do
        Beryl::Certificates::TrustStore.joins_mozilla_roots_to_the_system_bundle?.should be_false
        Beryl::Certificates::TrustStore.system.size.should eq(1)
      end
    ensure
      File.delete(bundle) if bundle && File.exists?(bundle)
    end
  end

  describe ".system_bundle_path" do
    it "reads the file SSL_CERT_FILE names, as OpenSSL and Go do" do
      bundle = File.tempname("beryl-ssl-cert-file", ".pem")
      File.write(bundle, Beryl::Certificates::TrustStore.mozilla.list_of_certificates.first.to_pem)
      with_ssl_cert_file(bundle) do
        Beryl::Certificates::TrustStore.system_bundle_path.should eq(bundle)
        Beryl::Certificates::TrustStore.system.size.should eq(1)
      end
    ensure
      File.delete(bundle) if bundle && File.exists?(bundle)
    end

    it "raises when SSL_CERT_FILE names a file that does not exist" do
      with_ssl_cert_file("/nonexistent/beryl-bundle.pem") do
        expect_raises(Beryl::Certificates::Error, /SSL_CERT_FILE/) do
          Beryl::Certificates::TrustStore.system_bundle_path
        end
      end
    end

    it "ignores an empty SSL_CERT_FILE" do
      operating_system_bundle = Beryl::Certificates::TrustStore::LIST_OF_SYSTEM_BUNDLE_PATHS.find { |candidate| File.exists?(candidate) }
      with_ssl_cert_file("") do
        if operating_system_bundle
          Beryl::Certificates::TrustStore.system_bundle_path.should eq(operating_system_bundle)
        else
          expect_raises(Beryl::Certificates::Error, /no system certificate bundle/) do
            Beryl::Certificates::TrustStore.system_bundle_path
          end
        end
      end
    end
  end
end

private def with_ssl_cert_file(value : String, &)
  previous = ENV["SSL_CERT_FILE"]?
  ENV["SSL_CERT_FILE"] = value
  yield
ensure
  ENV["SSL_CERT_FILE"] = previous
end
