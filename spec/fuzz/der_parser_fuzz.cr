require "../../src/beryl"
require "../support/x509_limbo"
require "./certificate_corpus"

# Mutation fuzzing of Beryl's DER and certificate code, seeded from the
# Certificate Transparency corpus and from every certificate and CRL in
# x509-limbo:
#
#     crystal-alpha build --release spec/fuzz/der_parser_fuzz.cr -o der_parser_fuzz
#     ./der_parser_fuzz ITERATIONS SEED [LIMBO_JSON]
#
# Each iteration stacks one to four mutations (`CertificateCorpus.mutate`)
# on a seed and hands the result to every reader in turn: the generic DER
# walk, `Certificate`, `CertificateRevocationList`, `SubjectPublicKeyInfo`
# (and its key decoding), `PrivateKeyFile`, `PEM`, and a full
# `ChainVerification` of the mutant as a leaf under its own seed chain.
#
# A finding is any exception that is not a `Beryl::Error` (an IndexError, an
# OverflowError, a failed cast), a reader taking longer than
# `LARGEST_TIME_PER_INPUT` every time it is run (one slow run whose repeats
# are fast is a collector pause, counted apart), or the process dying (which the run's exit
# status shows). Each finding prints the input in base64 so it can become a
# spec. The limits are Beryl's defaults: 64 KiB per certificate, nesting 32
# deep, the chain verification budget.
module DerParserFuzz
  LARGEST_TIME_PER_INPUT    = 10.milliseconds
  LARGEST_VERIFICATION_TIME = 60.milliseconds

  @@finding_count = 0
  @@pause_count = 0
  @@slowest = Time::Span.zero
  @@slowest_reader = ""

  def self.finding_count : Int32
    @@finding_count
  end

  # Walks every element of *bytes* with the DER reader, entering each
  # constructed element and each OCTET STRING or BIT STRING that holds DER.
  def self.walk(reader : Beryl::Encoding::DER::Reader) : Nil
    until reader.at_end?
      element = reader.read_element
      if element.tag.is_constructed
        reader.enter(element) { |inner| walk(inner) }
      elsif element.tag == Beryl::Encoding::DER::OCTET_STRING && element.content.size > 1 && element.content[0] == 0x30
        begin
          reader.enter_encapsulated(element, element.content) { |inner| walk(inner) }
        rescue Beryl::Encoding::Error
        end
      end
    end
  end

  def self.exercise(label : String, input : Bytes, limit : Time::Span = LARGEST_TIME_PER_INPUT, &) : Nil
    started_at = Time.instant
    begin
      yield
    rescue Beryl::Error
    rescue error
      @@finding_count += 1
      puts "FINDING #{label}: #{error.class}: #{error.message}: #{Base64.strict_encode(input)}"
      puts error.backtrace?.try(&.first(6).join("\n    ")) if @@finding_count <= 5
    end
    elapsed = Time.instant - started_at
    if elapsed > @@slowest
      @@slowest = elapsed
      @@slowest_reader = label
    end
    if elapsed > limit
      # Run again three times: a collector pause shows as a fast repeat,
      # and only an input that is slow every time is a finding.
      repeat = (1..3).min_of do
        repeat_started_at = Time.instant
        begin
          yield
        rescue Exception
        end
        Time.instant - repeat_started_at
      end
      if repeat > limit
        @@finding_count += 1
        puts "FINDING #{label}: #{elapsed.total_milliseconds.round(2)} ms (repeat #{repeat.total_milliseconds.round(2)} ms), over the #{limit.total_milliseconds} ms limit: #{Base64.strict_encode(input)}"
      else
        @@pause_count += 1
        puts "pause: #{label} #{elapsed.total_milliseconds.round(2)} ms once, #{repeat.total_microseconds.round(1)} µs run again"
      end
    end
  end

  def self.run(iterations : Int64, seed : UInt64, limbo_path : String?) : Nil
    list_of_entries = CertificateCorpus.read
    list_of_seeds = CertificateCorpus.distinct_certificates(list_of_entries)
    chain_by_leaf = Hash(Bytes, {Array(Beryl::Certificates::Certificate), Time}).new
    list_of_entries.each do |entry|
      next unless entry.entry_type == 0
      chain = entry.list_of_certificates[1..].compact_map do |der|
        Beryl::Certificates::Certificate.new(der)
      rescue Beryl::Certificates::MalformedCertificate
        nil
      end
      chain_by_leaf[entry.list_of_certificates.first] = {chain, entry.timestamp}
    end
    if limbo_path
      suite = X509Limbo::Suite.from_json(File.read(limbo_path))
      suite.testcases.each do |testcase|
        (testcase.trusted_certs + testcase.untrusted_intermediates + [testcase.peer_certificate] + testcase.crls).each do |pem|
          Beryl::Encoding::PEM.decode_blocks(pem).each { |block| list_of_seeds << block.bytes if block.bytes.size <= 65_536 }
        rescue Beryl::Encoding::Error
        end
      end
    end
    list_of_seeds.uniq!
    verification = Beryl::Certificates::ChainVerification.new(Beryl::Certificates::TrustStore.mozilla)
    list_of_leaves = chain_by_leaf.keys
    puts "fuzz: #{iterations} iterations, seed #{seed}, #{list_of_seeds.size} seed inputs (#{list_of_leaves.size} with a chain)"

    generator = Random::PCG32.new(seed)
    started_at = Time.instant
    iterations.times do |iteration|
      use_chain = generator.rand(16) == 0
      original = use_chain ? list_of_leaves.sample(generator) : list_of_seeds.sample(generator)
      input = original
      generator.rand(1..4).times { input = CertificateCorpus.mutate(input, list_of_seeds.sample(generator), generator) }

      exercise("DER walk", input) { walk(Beryl::Encoding::DER::Reader.new(input)) }
      certificate = nil
      exercise("Certificate", input) do
        certificate = Beryl::Certificates::Certificate.new(input)
        if parsed = certificate
          parsed.subject_public_key_info.verification_key
          parsed.subject.to_s
          parsed.list_of_dns_names
        end
      end
      exercise("CertificateRevocationList", input) { Beryl::Certificates::CertificateRevocationList.new(input) }
      exercise("SubjectPublicKeyInfo", input) { Beryl::Certificates::SubjectPublicKeyInfo.from_der(input).verification_key }
      exercise("PrivateKeyFile", input) { Beryl::Certificates::PrivateKeyFile.read_der(input) }
      exercise("PEM", input) { Beryl::Encoding::PEM.decode_blocks(Beryl::Encoding::PEM.encode(input, label: "CERTIFICATE")) }
      if use_chain && (leaf = certificate)
        chain, time = chain_by_leaf[original]
        exercise("ChainVerification", input, LARGEST_VERIFICATION_TIME) do
          name = leaf.list_of_dns_names.first?
          identity = name && !name.starts_with?("*") ? Beryl::Certificates::ServiceIdentity.new(name) : nil
          verification.verify(leaf, chain, identity: identity, time: time)
        rescue ArgumentError
        end
      end

      if (iteration + 1) % 1_000_000 == 0
        puts "fuzz: #{iteration + 1} inputs, #{@@finding_count} findings, #{(Time.instant - started_at).total_seconds.round(1)} s"
      end
    end
    puts "fuzz: #{iterations} inputs in #{(Time.instant - started_at).total_seconds.round(1)} s, #{@@finding_count} findings, #{@@pause_count} one-off pauses; slowest reader call #{@@slowest.total_milliseconds.round(3)} ms (#{@@slowest_reader})"
  end
end

iterations = ARGV[0]?.try(&.to_i64) || 100_000_i64
seed = ARGV[1]?.try(&.to_u64) || Random::Secure.rand(UInt64)
DerParserFuzz.run(iterations, seed, ARGV[2]?)
exit(DerParserFuzz.finding_count == 0 ? 0 : 1)
