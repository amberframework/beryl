require "../spec_helper"

# x509-limbo (C2SP/x509-limbo, pinned in spec/vectors/manifest.json): every
# case is run through `ChainVerification` with its own trust anchors,
# intermediates, validation time, peer name, purpose, key usage, CRLs and
# chain depth, and Beryl's verdict must equal the expected one. The cases
# Beryl does not take on are listed below with the reason; nothing else is
# skipped.

# Cases Beryl does not run, by feature, with the reason.
LIMBO_SKIPPED_FEATURES = {
  "has-mldsa" => "ML-DSA (RFC 9881) keys and signatures: Beryl has no ML-DSA",
}

# Cases whose expected result Beryl departs from: one side of a
# `conflicts_with` pair, or a rule where Beryl follows Go and OpenSSL.
LIMBO_SKIPPED_CONFLICTS = {
  "webpki::eku::ee-without-eku"                  => "conflicts with rfc5280::eku::ee-without-eku, which Beryl follows: a leaf without extended key usage is accepted, as Go and OpenSSL accept it, so private CAs for PostgreSQL and MySQL keep working",
  "webpki::ca-as-leaf"                           => "conflicts with rfc5280::ca-as-leaf and pathlen::validation-ignores-pathlen-in-leaf, which Beryl follows: a CA certificate may stand as leaf when its cA and keyCertSign agree",
  "rfc5280::nc::permitted-dns-match-noncritical" => "conflicts with webpki::nc::permitted-dns-match-noncritical, which Beryl follows: non-critical name constraints are applied, as the baseline requirements allow",
  "webpki::cn::not-in-san"                       => "contradicted by 99 other cases (rfc5280::nc::permitted-dns-match-more, webpki::san, the BetterTLS suites) that expect a leaf whose common name is not among its dNSName entries to verify; every harness on x509-limbo.com accepts it",
  "rfc5280::ski::root-missing-ski"               => "contradicted by Mozilla's root set: TWCA Global Root CA has no subject key identifier, and Beryl accepts the roots Mozilla trusts (an intermediate still needs one)",
  "rfc5280::aki::cross-signed-root-missing-aki"  => "marked pedantic, and contradicted by cve::cve-2024-0567, whose trust anchor is cross-signed and has no authority key identifier yet must verify",
  "rfc5280::aki::leaf-missing-aki"               => "Beryl follows Go crypto/x509 and OpenSSL, which find the issuer of a leaf without an authority key identifier by name and verify its signature; private CAs for PostgreSQL and MySQL often omit the extension",
  "rfc5280::aki::intermediate-missing-aki"       => "Beryl follows Go crypto/x509 and OpenSSL, which find the issuer of an intermediate without an authority key identifier by name and verify its signature; private CAs for PostgreSQL and MySQL often omit the extension",
}

# The skip reason for *testcase*, or `nil` when it runs.
def limbo_skip_reason(testcase : X509Limbo::Testcase) : String?
  if reason = LIMBO_SKIPPED_CONFLICTS[testcase.id]?
    return reason
  end
  testcase.features.each do |feature|
    if reason = LIMBO_SKIPPED_FEATURES[feature]?
      return reason
    end
  end
  nil
end

# Beryl's verdict on *testcase*: `nil` when the chain verifies, otherwise
# the reason it was refused.
def limbo_refusal(testcase : X509Limbo::Testcase, limits : Beryl::Certificates::ChainVerification::Limits) : String?
  anchors = testcase.trusted_certs.compact_map do |pem|
    Beryl::Certificates::Certificate.list_from_pem(pem).first?
  rescue Beryl::Certificates::MalformedCertificate
    nil
  end
  intermediates = testcase.untrusted_intermediates.compact_map do |pem|
    Beryl::Certificates::Certificate.list_from_pem(pem).first?
  rescue Beryl::Certificates::MalformedCertificate
    nil
  end
  leaf = begin
    Beryl::Certificates::Certificate.list_from_pem(testcase.peer_certificate).first?
  rescue error : Beryl::Certificates::MalformedCertificate
    return "the leaf does not parse: #{error.message}"
  end
  return "no leaf" unless leaf

  revocation_lists = [] of Beryl::Certificates::CertificateRevocationList
  testcase.crls.each do |pem|
    revocation_lists.concat(Beryl::Certificates::CertificateRevocationList.list_from_pem(pem))
  rescue error : Beryl::Certificates::MalformedCertificate
    return "a CRL does not parse: #{error.message}"
  end

  identity = nil
  if peer_name = testcase.expected_peer_name
    if {"DNS", "IP"}.includes?(peer_name.kind) && !peer_name.value.empty?
      begin
        identity = Beryl::Certificates::ServiceIdentity.new(peer_name.value)
      rescue error : ArgumentError
        return "the peer name is not a name Beryl accepts: #{error.message}"
      end
    end
  end

  purpose = testcase.validation_kind == "CLIENT" ? Beryl::Certificates::Purpose::ClientAuthentication : Beryl::Certificates::Purpose::ServerAuthentication
  required_key_usage = testcase.key_usage.includes?("digitalSignature") ? Beryl::Certificates::KeyUsage::DigitalSignature : Beryl::Certificates::KeyUsage::None
  time = testcase.validation_time.try { |text| Time.parse_rfc3339(text) } || Time.utc

  verification = Beryl::Certificates::ChainVerification.new(Beryl::Certificates::TrustStore.new(anchors), limits: limits)
  verification.verify(leaf, intermediates, identity: identity, purpose: purpose, time: time,
    required_key_usage: required_key_usage, list_of_revocation_lists: revocation_lists,
    largest_intermediate_count: testcase.max_chain_depth)
  nil
rescue error : Beryl::Certificates::VerificationFailed
  "#{error.reason}: #{error.message}"
end

describe "x509-limbo" do
  it "decides every applicable case as expected" do
    suite = X509Limbo::Suite.from_json(VectorFile.read("x509-limbo/limbo.json"))
    # A debug build verifies signatures tens of times slower than a release
    # build, so the time bound is widened there; the signature-count bound
    # still stops the pathological cases.
    limits = Beryl::Certificates::ChainVerification::Limits.new(
      largest_elapsed_time: {% if flag?(:release) %} 50.milliseconds {% else %} 5.seconds {% end %}
    )

    list_of_mismatches = [] of String
    skipped_by_reason = Hash(String, Array(String)).new { |hash, key| hash[key] = [] of String }
    run_count = 0
    matched_by_result = Hash(String, Int32).new(0)
    suite.testcases.each do |testcase|
      if reason = limbo_skip_reason(testcase)
        skipped_by_reason[reason] << testcase.id
        next
      end
      run_count += 1
      refusal = limbo_refusal(testcase, limits)
      verdict = refusal ? "FAILURE" : "SUCCESS"
      if verdict == testcase.expected_result
        matched_by_result[verdict] += 1
      else
        list_of_mismatches << "#{testcase.id}: expected #{testcase.expected_result}, Beryl #{verdict}#{refusal ? " (#{refusal})" : ""}"
      end
    end

    puts
    puts "x509-limbo (#{suite.testcases.size} cases): #{run_count} run, #{matched_by_result.values.sum} matched " \
         "(#{matched_by_result["SUCCESS"]} SUCCESS, #{matched_by_result["FAILURE"]} FAILURE), #{list_of_mismatches.size} mismatched, " \
         "#{skipped_by_reason.values.sum(&.size)} skipped"
    skipped_by_reason.each do |reason, list_of_ids|
      puts "  skipped #{list_of_ids.size}: #{reason}"
      list_of_ids.each { |id| puts "    #{id}" }
    end
    list_of_mismatches.each { |mismatch| puts "  MISMATCH #{mismatch}" }
    list_of_mismatches.size.should eq(0)
  end
end
