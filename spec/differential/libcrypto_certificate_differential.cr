require "openssl"
require "../../src/beryl"
require "../fuzz/certificate_corpus"

# Differential of Beryl's certificate code against libcrypto (OpenSSL
# 4.1.0), over the Certificate Transparency corpus that
# scripts/fetch_certificate_corpus.rb installs:
#
#     crystal-alpha build --release spec/differential/libcrypto_certificate_differential.cr -o certificate_differential
#     ./certificate_differential parse        every certificate: Beryl's reading against d2i_X509
#     ./certificate_differential verify       every logged X.509 chain: ChainVerification against X509_verify_cert
#     ./certificate_differential mutate N     N mutated certificates (Frankencert style): reading against d2i_X509
#
# Seeds and counts come from the command line (`mutate N [seed]`) and are
# printed. Each disagreement is printed with its class, and the program
# ends with the count of each class; the written explanation of every class
# is in docs/certificates.md.
#
# OpenSSL "accepts" a certificate when d2i_X509 reads it, consumes every
# byte, and sets no EXFLAG_INVALID while caching its extensions (OpenSSL
# reads extension contents lazily and refuses a certificate whose
# extensions are malformed only when it is used). Beryl accepts when
# `Certificate.new` returns.
lib LibCrypto
  fun beryl_certificate_d2i_x509 = d2i_X509(a : X509*, ppin : UInt8**, length : Long) : X509
  fun beryl_certificate_x509_free = X509_free(a : X509)
  fun beryl_certificate_x509_get_extension_flags = X509_get_extension_flags(certificate : X509) : UInt32
  fun beryl_certificate_store_new = X509_STORE_new : X509_STORE
  fun beryl_certificate_store_free = X509_STORE_free(store : X509_STORE)
  fun beryl_certificate_store_add_cert = X509_STORE_add_cert(ctx : X509_STORE, x : X509) : Int
  fun beryl_certificate_store_ctx_new = X509_STORE_CTX_new : X509_STORE_CTX
  fun beryl_certificate_store_ctx_free = X509_STORE_CTX_free(context : X509_STORE_CTX)
  fun beryl_certificate_store_ctx_init = X509_STORE_CTX_init(context : X509_STORE_CTX, store : X509_STORE, leaf : X509, chain : Void*) : Int
  fun beryl_certificate_store_ctx_get0_param = X509_STORE_CTX_get0_param(context : X509_STORE_CTX) : X509VerifyParam
  fun beryl_certificate_store_ctx_get_error = X509_STORE_CTX_get_error(context : X509_STORE_CTX) : Int
  fun beryl_certificate_verify_cert = X509_verify_cert(x : X509_STORE_CTX) : Int
  fun beryl_certificate_verify_cert_error_string = X509_verify_cert_error_string(error : LibC::Long) : LibC::Char*
  fun beryl_certificate_param_set_time = X509_VERIFY_PARAM_set_time(parameters : X509VerifyParam, time : LibC::TimeT)
  fun beryl_certificate_param_set1_host = X509_VERIFY_PARAM_set1_host(param : X509VerifyParam, name : UInt8*, len : SizeT) : Int
  fun beryl_certificate_param_set_purpose = X509_VERIFY_PARAM_set_purpose(parameters : X509VerifyParam, purpose : Int) : Int
  fun beryl_certificate_sk_new_null = OPENSSL_sk_new_null : Void*
  fun beryl_certificate_sk_push = OPENSSL_sk_push(stack : Void*, item : Void*) : Int
  fun beryl_certificate_sk_free = OPENSSL_sk_free(st : Void*)
  fun beryl_certificate_openssl_version = OpenSSL_version(kind : LibC::Int) : LibC::Char*
  fun beryl_certificate_err_clear_error = ERR_clear_error
  fun beryl_certificate_err_get_error_all = ERR_get_error_all(file : Char**, line : Int*, function : Char**, data : Char**, flags : Int*) : ULong
  fun beryl_certificate_err_reason_error_string = ERR_reason_error_string(e : ULong) : Char*
end

module CertificateDifferential
  EXFLAG_INVALID     = 0x80_u32
  PURPOSE_SSL_SERVER =        2
  LARGEST_PARSE_TIME = 10.milliseconds

  # OpenSSL's verdict on one DER certificate: accepted, or the reason.
  def self.openssl_refusal(der : Bytes) : String?
    pointer = der.to_unsafe
    certificate = LibCrypto.beryl_certificate_d2i_x509(nil, pointerof(pointer), der.size)
    reason = last_error_reason
    return "d2i_X509 refused it: #{reason}" if certificate.null?

    begin
      return "d2i_X509 left #{der.size - (pointer - der.to_unsafe)} bytes unread" unless pointer - der.to_unsafe == der.size
      flags = LibCrypto.beryl_certificate_x509_get_extension_flags(certificate)
      reason = last_error_reason
      return "EXFLAG_INVALID: #{reason}" if flags & EXFLAG_INVALID != 0
      nil
    ensure
      LibCrypto.beryl_certificate_x509_free(certificate)
    end
  end

  # The innermost libcrypto error (the first queued) with the field and
  # type libcrypto names for it; the error queue is emptied.
  def self.last_error_reason : String
    list_of_reasons = [] of String
    loop do
      data = Pointer(LibC::Char).null
      flags = 0
      code = LibCrypto.beryl_certificate_err_get_error_all(nil, nil, nil, pointerof(data), pointerof(flags))
      break if code == 0
      text = LibCrypto.beryl_certificate_err_reason_error_string(code)
      reason = text.null? ? "error #{code}" : String.new(text)
      detail = data.null? ? "" : String.new(data)
      list_of_reasons << (detail.empty? ? reason : "#{reason} (#{detail})")
    end
    LibCrypto.beryl_certificate_err_clear_error
    return "no error queued" if list_of_reasons.empty?
    # The innermost error and the innermost one naming a field.
    innermost = list_of_reasons.first
    field = list_of_reasons.find(&.includes?("Field="))
    field && field != innermost ? "#{innermost}; #{field}" : innermost
  end

  def self.openssl_certificate(der : Bytes) : LibCrypto::X509
    pointer = der.to_unsafe
    LibCrypto.beryl_certificate_d2i_x509(nil, pointerof(pointer), der.size)
  end

  # Beryl's verdict: accepted, or a class of refusal (the message with its
  # numbers and offsets removed, so like refusals group together).
  def self.beryl_refusal(der : Bytes) : String?
    Beryl::Certificates::Certificate.new(der)
    nil
  rescue error : Beryl::Certificates::MalformedCertificate
    normalize(error.message || "")
  end

  def self.normalize(message : String) : String
    String.build do |io|
      previous_was_digit = false
      message.each_char do |character|
        if character.ascii_number?
          io << '#' unless previous_was_digit
          previous_was_digit = true
        else
          io << character
          previous_was_digit = false
        end
      end
    end
  end

  def self.run_parse(list_of_entries : Array(CertificateCorpus::Entry)) : Bool
    unique = Set(Bytes).new
    list_of_entries.each { |entry| entry.list_of_certificates.each { |certificate| unique << certificate } }
    puts "parse: #{unique.size} distinct certificates from #{list_of_entries.size} log entries"
    tally = Hash(String, Int32).new(0)
    agreed = 0
    slowest = Time::Span.zero
    slowest_der = Bytes.empty
    # The first reading initializes constants (object identifiers, tables);
    # it is done once before timing starts.
    beryl_refusal(unique.first)
    list_of_times = [] of Float64
    unique.each do |der|
      started_at = Time.instant
      beryl = beryl_refusal(der)
      elapsed = Time.instant - started_at
      list_of_times << elapsed.total_microseconds
      if elapsed > slowest
        slowest = elapsed
        slowest_der = der
      end
      openssl = openssl_refusal(der)
      if beryl.nil? == openssl.nil?
        agreed += 1
        tally["agree: #{beryl.nil? ? "both accept" : "both refuse"}"] += 1
      else
        label = beryl ? "Beryl refuses (#{beryl}), OpenSSL accepts" : "Beryl accepts, OpenSSL refuses (#{openssl})"
        tally["DISAGREE: #{label}"] += 1
        puts "disagreement: #{label}: #{Base64.strict_encode(der)}" if tally["DISAGREE: #{label}"] <= 3
      end
    end
    print_tally(tally)
    list_of_times.sort!
    puts "parse: #{agreed} of #{unique.size} agree; Beryl parse median #{list_of_times[list_of_times.size // 2].round(1)} µs, 99.9th percentile #{list_of_times[(list_of_times.size * 999) // 1000].round(1)} µs, slowest #{slowest.total_microseconds.round(1)} µs"
    # The slowest certificate read again 100 times: a one-off pause (the
    # garbage collector) shows as a fast repeat.
    repeat_started_at = Time.instant
    100.times { beryl_refusal(slowest_der) }
    puts "parse: the slowest certificate (#{slowest_der.size} bytes) read again 100 times: #{((Time.instant - repeat_started_at).total_microseconds / 100).round(1)} µs each"
    agreed == unique.size
  end

  def self.run_verify(list_of_entries : Array(CertificateCorpus::Entry)) : Bool
    roots_pem = Beryl::Certificates::TrustStore::MOZILLA_ROOTS_PEM
    store = LibCrypto.beryl_certificate_store_new
    Beryl::Encoding::PEM.decode(roots_pem, label: "CERTIFICATE").each do |der|
      certificate = openssl_certificate(der)
      LibCrypto.beryl_certificate_store_add_cert(store, certificate) unless certificate.null?
      LibCrypto.beryl_certificate_x509_free(certificate) unless certificate.null?
    end
    LibCrypto.beryl_certificate_err_clear_error
    verification = Beryl::Certificates::ChainVerification.new(Beryl::Certificates::TrustStore.mozilla)

    tally = Hash(String, Int32).new(0)
    compared = 0
    agreed = 0
    slowest = Time::Span.zero
    list_of_entries.each do |entry|
      category = entry.entry_type == 0 ? "certificate" : "precertificate"
      leaf_der = entry.list_of_certificates.first
      leaf = begin
        Beryl::Certificates::Certificate.new(leaf_der)
      rescue Beryl::Certificates::MalformedCertificate
        tally["skipped: the leaf does not parse in Beryl"] += 1
        next
      end
      name = leaf.list_of_dns_names.find { |candidate| !candidate.starts_with?("*.") } ||
             leaf.list_of_dns_names.first?.try { |wildcard| "beryl-differential#{wildcard[1..]}" }
      category += name ? ", host name checked" : ", no DNS name: purpose only"
      compared += 1

      intermediates = entry.list_of_certificates[1..].compact_map do |der|
        Beryl::Certificates::Certificate.new(der)
      rescue Beryl::Certificates::MalformedCertificate
        nil
      end
      started_at = Time.instant
      beryl = begin
        verification.verify(leaf, intermediates, identity: name.try { |host| Beryl::Certificates::ServiceIdentity.new(host) }, time: entry.timestamp)
        nil
      rescue error : Beryl::Certificates::VerificationFailed
        "#{error.reason}: #{normalize(error.message || "")}"
      rescue error : ArgumentError
        "name: #{error.message}"
      end
      elapsed = Time.instant - started_at
      slowest = elapsed if elapsed > slowest

      openssl = openssl_verify(store, entry, name)
      if beryl.nil? == openssl.nil?
        agreed += 1
        tally["agree (#{category}): #{beryl.nil? ? "both verify" : "both refuse"}"] += 1
      else
        label = beryl ? "Beryl refuses (#{beryl.split(": the ").first(2).join(": the ")[0, 220]}), OpenSSL verifies" : "Beryl verifies, OpenSSL refuses (#{openssl})"
        label = "#{category}: #{label}"
        tally["DISAGREE: #{label}"] += 1
        if tally["DISAGREE: #{label}"] <= 2
          puts "disagreement: #{label}: name #{name} at #{entry.timestamp}: #{entry.list_of_certificates.map { |der| Base64.strict_encode(der) }.join(" ")}"
        end
      end
    end
    LibCrypto.beryl_certificate_store_free(store)
    print_tally(tally)
    puts "verify: #{agreed} of #{compared} chains agree; slowest Beryl verification #{slowest.total_milliseconds.round(2)} ms"
    agreed == compared
  end

  def self.openssl_verify(store : LibCrypto::X509_STORE, entry : CertificateCorpus::Entry, name : String?) : String?
    leaf = openssl_certificate(entry.list_of_certificates.first)
    return "the leaf does not parse" if leaf.null?
    chain = LibCrypto.beryl_certificate_sk_new_null
    list_of_owned = [] of LibCrypto::X509
    entry.list_of_certificates[1..].each do |der|
      certificate = openssl_certificate(der)
      next if certificate.null?
      list_of_owned << certificate
      LibCrypto.beryl_certificate_sk_push(chain, certificate.as(Void*))
    end
    context = LibCrypto.beryl_certificate_store_ctx_new
    LibCrypto.beryl_certificate_store_ctx_init(context, store, leaf, chain)
    parameters = LibCrypto.beryl_certificate_store_ctx_get0_param(context)
    LibCrypto.beryl_certificate_param_set_time(parameters, entry.timestamp.to_unix)
    LibCrypto.beryl_certificate_param_set_purpose(parameters, PURPOSE_SSL_SERVER)
    LibCrypto.beryl_certificate_param_set1_host(parameters, name.to_unsafe, name.bytesize) if name
    verdict = LibCrypto.beryl_certificate_verify_cert(context)
    refusal = verdict == 1 ? nil : String.new(LibCrypto.beryl_certificate_verify_cert_error_string(LibCrypto.beryl_certificate_store_ctx_get_error(context)))
    LibCrypto.beryl_certificate_err_clear_error
    LibCrypto.beryl_certificate_store_ctx_free(context)
    LibCrypto.beryl_certificate_sk_free(chain)
    list_of_owned.each { |certificate| LibCrypto.beryl_certificate_x509_free(certificate) }
    LibCrypto.beryl_certificate_x509_free(leaf)
    refusal
  end

  def self.run_mutate(list_of_entries : Array(CertificateCorpus::Entry), count : Int32, seed : UInt64) : Bool
    unique = Set(Bytes).new
    list_of_entries.each { |entry| entry.list_of_certificates.each { |certificate| unique << certificate } }
    seeds = unique.to_a
    puts "mutate: #{count} mutants from #{seeds.size} seed certificates, seed #{seed}"
    generator = Random::PCG32.new(seed)
    tally = Hash(String, Int32).new(0)
    agreed = 0
    slowest = Time::Span.zero
    crashes = 0
    slow_count = 0
    count.times do |index|
      der = CertificateCorpus.mutate(seeds.sample(generator), seeds.sample(generator), generator)
      started_at = Time.instant
      beryl = begin
        beryl_refusal(der)
      rescue error
        crashes += 1
        puts "CRASH #{error.class}: #{error.message}: #{Base64.strict_encode(der)}"
        "crash"
      end
      elapsed = Time.instant - started_at
      slowest = elapsed if elapsed > slowest
      if elapsed > LARGEST_PARSE_TIME
        # Read again three times: a collector pause shows as a fast repeat,
        # and only an input that is slow every time counts.
        repeat = (1..3).min_of do
          repeat_started_at = Time.instant
          beryl_refusal(der) rescue nil
          Time.instant - repeat_started_at
        end
        if repeat > LARGEST_PARSE_TIME
          slow_count += 1
          puts "SLOW #{elapsed.total_milliseconds} ms (repeat #{repeat.total_milliseconds} ms): #{Base64.strict_encode(der)}"
        else
          puts "pause: #{elapsed.total_milliseconds.round(2)} ms once, #{repeat.total_microseconds.round(1)} µs read again"
        end
      end
      openssl = openssl_refusal(der)
      if beryl.nil? == openssl.nil?
        agreed += 1
        tally["agree: #{beryl.nil? ? "both accept" : "both refuse"}"] += 1
      else
        label = beryl ? "Beryl refuses (#{beryl}), OpenSSL accepts" : "Beryl accepts, OpenSSL refuses (#{openssl})"
        tally["DISAGREE: #{label}"] += 1
        puts "disagreement: #{label}: #{Base64.strict_encode(der)}" if tally["DISAGREE: #{label}"] <= (beryl ? 2 : 20)
      end
    end
    print_tally(tally)
    puts "mutate: #{agreed} of #{count} agree; #{crashes} crashes; slowest Beryl parse #{slowest.total_microseconds.round(1)} µs (limit #{LARGEST_PARSE_TIME.total_milliseconds} ms, #{slow_count} over it)"
    crashes == 0 && slow_count == 0
  end

  def self.print_tally(tally : Hash(String, Int32)) : Nil
    tally.to_a.sort_by { |(label, count)| {label.starts_with?("DISAGREE") ? 0 : 1, -count} }.each do |(label, count)|
      puts "  #{count.to_s.rjust(9)}  #{label}"
    end
  end
end

puts "libcrypto: #{String.new(LibCrypto.beryl_certificate_openssl_version(0))}"
list_of_entries = CertificateCorpus.read
# Exit status 1: a parse or verify disagreement, or in mutate a crash or a
# reading over the time limit (mutants that OpenSSL and Beryl judge
# differently are expected and explained in docs/certificates.md).
passed = case ARGV[0]?
         when "parse"  then CertificateDifferential.run_parse(list_of_entries)
         when "verify" then CertificateDifferential.run_verify(list_of_entries)
         when "mutate"
           count = ARGV[1]?.try(&.to_i) || 1_000_000
           seed = ARGV[2]?.try(&.to_u64) || Random::Secure.rand(UInt64)
           CertificateDifferential.run_mutate(list_of_entries, count, seed)
         else
           STDERR.puts "usage: certificate_differential parse | verify | mutate [count] [seed]"
           exit 2
         end
exit(passed ? 0 : 1)
