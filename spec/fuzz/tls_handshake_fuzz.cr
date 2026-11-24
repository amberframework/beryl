require "base64"
require "../../src/beryl"
require "../support/der_writer"
require "../support/test_certificate_authority"
require "../support/tls_harness"
require "../support/rfc8448_trace"

# Mutation fuzzing of Beryl's TLS 1.3 handshake, over recorded handshakes
# (plan §4, "Fuzzing"):
#
#     crystal-alpha build --release spec/fuzz/tls_handshake_fuzz.cr -o tls_handshake_fuzz
#     ./tls_handshake_fuzz ITERATIONS SEED
#
# The corpus is recorded when the run starts: loopback handshakes for every
# suite, group and key type, with HelloRetryRequest, ALPN and resumption,
# plus every handshake message of RFC 8448. Each iteration runs four
# targets, each on its own mutant (one to four stacked mutations):
#
# - decoders: a recorded handshake message through every message decoder
#   and every extension decoder;
# - server: the recorded plaintext ClientHello records (both, after a
#   HelloRetryRequest) through `ServerHandshake`;
# - client hello: the recorded plaintext ServerHello or HelloRetryRequest
#   record through `ClientHandshake`, with the client's randomness fixed so
#   its ClientHello matches the recording;
# - client flight: one message of the server's encrypted flight
#   (EncryptedExtensions, Certificate, CertificateVerify, Finished)
#   mutated, then sealed again under the server handshake key, so the
#   client parses the mutant after decryption.
#
# A finding is any exception other than `Beryl::Error` or the end of the
# script (`IO::Error`), an input that takes over `LARGEST_TIME_PER_INPUT`
# every time it runs, or the process dying. Findings print the target and
# the input in base64, so each can become a spec.
module TlsHandshakeFuzz
  alias TLS = Beryl::TLS

  LARGEST_TIME_PER_INPUT = 100.milliseconds

  # A recorded full or resumed handshake, with what replaying the client
  # needs.
  class Recording
    getter label : String
    getter client_to_server = IO::Memory.new
    getter server_to_client = IO::Memory.new
    getter list_of_client_random_values : Array(Bytes)
    getter client_x25519_secret : Bytes?
    getter client_p256_secret : Bytes?
    getter client_context : TLS::Context::Client
    getter list_of_messages = [] of Bytes

    def initialize(@label, @list_of_client_random_values, @client_x25519_secret, @client_p256_secret, @client_context)
    end

    # A client context with the same settings and fixed randomness, so it
    # sends the recorded ClientHello again.
    def replay_context : TLS::Context::Client
      randomness = TlsHarness::FixedRandomness.new
      @list_of_client_random_values.each { |value| randomness.list_of_byte_strings << value }
      if secret = @client_x25519_secret
        randomness.list_of_x25519_keys << Beryl::Crypto::V1::X25519::PrivateKey.new(secret)
      end
      if secret = @client_p256_secret
        randomness.list_of_p256_keys << Beryl::Crypto::V1::P256::PrivateKey.new(secret)
      end
      context = TLS::Context::Client.new
      context.randomness = randomness
      context.certificate_verifier = @client_context.certificate_verifier
      context.list_of_cipher_suites = @client_context.list_of_cipher_suites
      context.list_of_groups = @client_context.list_of_groups
      context.list_of_key_share_groups = @client_context.list_of_key_share_groups
      context.list_of_alpn_protocols = @client_context.list_of_alpn_protocols
      context
    end
  end

  # Copies one direction of a socket pair into a recording.
  class TappedIO < IO
    def initialize(@inner : IO, @written : IO::Memory)
    end

    def read(slice : Bytes) : Int32
      @inner.read(slice)
    end

    def write(slice : Bytes) : Nil
      @written.write(slice)
      @inner.write(slice)
    end

    def flush : Nil
      @inner.flush
    end

    def close : Nil
      @inner.close
    end
  end

  # A record layer that keeps every handshake message it reads.
  class RecordingRecordLayer < TLS::RecordLayer
    def initialize(io : IO, @list_of_messages : Array(Bytes))
      super(io)
    end

    def read_handshake_message : Bytes
      message = super
      @list_of_messages << message.dup
      message
    end
  end

  @@finding_count = 0
  # How each target ended, so a run shows it reached deep states.
  @@outcome_counts = Hash(String, Int64).new(0_i64)
  @@pause_count = 0
  @@server_context : TLS::Context::Server? = nil

  def self.finding_count : Int32
    @@finding_count
  end

  # Records one handshake with *server_context* and a client whose
  # randomness is fixed.
  def self.record(label : String, server_context : TLS::Context::Server, client_context : TLS::Context::Client) : Recording
    list_of_values = [Random::Secure.random_bytes(32), Random::Secure.random_bytes(32), Random::Secure.random_bytes(16)]
    x25519_secret = Random::Secure.random_bytes(32)
    p256_key = Beryl::Crypto::V1::P256::PrivateKey.generate
    recording = Recording.new(label, list_of_values, x25519_secret, p256_key.to_slice, client_context)
    randomness = TlsHarness::FixedRandomness.new
    list_of_values.each { |value| randomness.list_of_byte_strings << value }
    randomness.list_of_x25519_keys << Beryl::Crypto::V1::X25519::PrivateKey.new(x25519_secret)
    randomness.list_of_p256_keys << p256_key
    client_context.randomness = randomness

    client_io, server_io = UNIXSocket.pair
    done = Channel(Nil).new
    spawn do
      layer = RecordingRecordLayer.new(TappedIO.new(server_io, recording.server_to_client), recording.list_of_messages)
      TLS::ServerHandshake.new(layer, server_context).perform
    rescue error
      STDERR.puts "recording #{label}: the server failed: #{error.message}"
    ensure
      done.send(nil)
    end
    layer = RecordingRecordLayer.new(TappedIO.new(client_io, recording.client_to_server), recording.list_of_messages)
    outcome = TLS::ClientHandshake.new(layer, client_context, "localhost").perform
    done.receive
    # Read the server's tickets so a later recording can resume.
    if server_context.session_tickets_enabled?
      server_context.session_ticket_count.times do
        message = layer.read_after_handshake
        next unless message && message[0].handshake?
        ticket = TLS::Messages::NewSessionTicket.decode(TLS::Messages.unwrap(message[1])[1])
        hash = outcome.cipher_suite.hash_algorithm
        client_context.session_cache.store(TLS::SessionTicket.new("localhost", outcome.cipher_suite,
          TLS::KeySchedule.resumption_pre_shared_key(hash, outcome.resumption_master_secret, ticket.ticket_nonce),
          ticket.ticket, ticket.ticket_age_add, Time.instant, ticket.ticket_lifetime.seconds, outcome.alpn_protocol,
          client_context.certificate_verifier))
      end
    end
    client_io.close
    server_io.close
    recording
  end

  def self.build_corpus : Array(Recording)
    list_of_recordings = [] of Recording
    TestCertificateAuthority::KeyKind.each do |key_kind|
      server_context = TlsHarness.server_context(key_kind)
      server_context.alpn_protocols = ["h2", "http/1.1"]
      @@server_context ||= server_context
      TLS::CipherSuite.each do |suite|
        client_context = TlsHarness.client_context
        client_context.list_of_cipher_suites = [suite]
        client_context.alpn_protocols = ["http/1.1"]
        list_of_recordings << record("#{key_kind} #{suite} x25519", server_context, client_context)
        # The same client again, resuming with the ticket it was sent.
        list_of_recordings << record("#{key_kind} #{suite} resumed", server_context, client_context)
      end
      retry_server = TlsHarness.server_context(key_kind)
      retry_server.list_of_groups = [TLS::NamedGroup::Secp256r1]
      list_of_recordings << record("#{key_kind} HelloRetryRequest", retry_server, TlsHarness.client_context)
    end
    list_of_recordings
  end

  # Splits a stream into its records.
  def self.records_of(stream : Bytes) : Array(Bytes)
    list_of_records = [] of Bytes
    offset = 0
    while offset + 5 <= stream.size
      length = (stream[offset + 3].to_i << 8) | stream[offset + 4].to_i
      break if offset + 5 + length > stream.size
      list_of_records << stream[offset, 5 + length]
      offset += 5 + length
    end
    list_of_records
  end

  # One TLS-shaped mutation of *input*: a bit flipped, a byte set,
  # inserted or deleted, a 16- or 24-bit length nudged, a range spliced in
  # from *donor*, a tail cut off, or a range repeated.
  def self.mutate(input : Bytes, donor : Bytes, generator : Random) : Bytes
    return Bytes[generator.rand(256).to_u8] if input.empty?
    copy = input.dup
    case generator.rand(8)
    when 0
      copy[generator.rand(copy.size)] ^= (1_u8 << generator.rand(8))
      copy
    when 1
      copy[generator.rand(copy.size)] = generator.rand(256).to_u8
      copy
    when 2
      index = generator.rand(copy.size + 1)
      Bytes.new(copy.size + 1) { |position| position < index ? copy[position] : (position == index ? generator.rand(256).to_u8 : copy[position - 1]) }
    when 3
      index = generator.rand(copy.size)
      Bytes.new(copy.size - 1) { |position| position < index ? copy[position] : copy[position + 1] }
    when 4
      return copy if copy.size < 2
      index = generator.rand(copy.size - 1)
      value = ((copy[index].to_i << 8) | copy[index + 1].to_i) + generator.rand(-3..3)
      value = value.clamp(0, 0xFFFF)
      copy[index] = (value >> 8).to_u8
      copy[index + 1] = (value & 0xFF).to_u8
      copy
    when 5
      return copy if donor.empty?
      start = generator.rand(copy.size)
      length = generator.rand(1..Math.min(64, copy.size - start))
      donor_start = generator.rand(donor.size)
      donor_length = generator.rand(1..Math.min(64, donor.size - donor_start))
      io = IO::Memory.new
      io.write(copy[0, start])
      io.write(donor[donor_start, donor_length])
      io.write(copy[start + length, copy.size - start - length])
      io.to_slice
    when 6
      copy[0, generator.rand(copy.size)]
    else
      start = generator.rand(copy.size)
      length = generator.rand(1..Math.min(32, copy.size - start))
      io = IO::Memory.new
      io.write(copy[0, start + length])
      io.write(copy[start, length])
      io.write(copy[start + length, copy.size - start - length])
      io.to_slice
    end
  end

  def self.mutant(input : Bytes, donor : Bytes, generator : Random) : Bytes
    result = input
    generator.rand(1..4).times { result = mutate(result, donor, generator) }
    result
  end

  def self.exercise(label : String, input : Bytes, &) : Nil
    started_at = Time.instant
    begin
      yield
      @@outcome_counts["#{label}: completed"] += 1
    rescue error : Beryl::TLS::Error
      @@outcome_counts["#{label}: #{error.alert_description}"] += 1
    rescue Beryl::Error
      @@outcome_counts["#{label}: other Beryl error"] += 1
    rescue IO::Error
      @@outcome_counts["#{label}: end of input"] += 1
    rescue error
      report_finding(label, "#{error.class}: #{error.message}", input, error)
    end
    elapsed = Time.instant - started_at
    return unless elapsed > LARGEST_TIME_PER_INPUT
    repeat = (1..3).min_of do
      repeat_started_at = Time.instant
      begin
        yield
      rescue Exception
      end
      Time.instant - repeat_started_at
    end
    if repeat > LARGEST_TIME_PER_INPUT
      report_finding(label, "#{elapsed.total_milliseconds.round(1)} ms (repeat #{repeat.total_milliseconds.round(1)} ms)", input, nil)
    else
      @@pause_count += 1
    end
  end

  private def self.report_finding(label : String, reason : String, input : Bytes, error : Exception?) : Nil
    @@finding_count += 1
    STDOUT.puts "FINDING #{label}: #{reason}: #{Base64.strict_encode(input)}"
    if error && @@finding_count <= 5
      STDOUT.puts error.backtrace?.try(&.first(8).join("\n    "))
    end
  end

  # Every decoder on *message*, and every extension decoder on each of
  # its extensions.
  def self.decode_everything(message : Bytes) : Nil
    return if message.size < 4
    body = message[4..]
    codec = TLS::Messages::ExtensionCodec
    list_of_extensions = [] of TLS::Messages::Extension
    attempt { list_of_extensions.concat(TLS::Messages::ClientHello.decode(body).list_of_extensions) }
    attempt { list_of_extensions.concat(TLS::Messages::ServerHello.decode(body).list_of_extensions) }
    attempt { list_of_extensions.concat(TLS::Messages::EncryptedExtensions.decode(body).list_of_extensions) }
    attempt { TLS::Messages::CertificateMessage.decode(body).list_of_entries.each { |entry| Beryl::Certificates::Certificate.new(entry.certificate_data) } }
    attempt { list_of_extensions.concat(TLS::Messages::CertificateRequest.decode(body).list_of_extensions) }
    attempt { TLS::Messages::CertificateVerify.decode(body) }
    attempt { TLS::Messages::Finished.decode(body, 32) }
    attempt { list_of_extensions.concat(TLS::Messages::NewSessionTicket.decode(body).list_of_extensions) }
    attempt { TLS::Messages::KeyUpdate.decode(body) }
    list_of_extensions.each do |extension|
      contents = extension.contents
      attempt { codec.decode_server_name(contents) }
      attempt { codec.decode_u16_list(contents) }
      attempt { codec.decode_client_supported_versions(contents) }
      attempt { codec.decode_selected_version(contents) }
      attempt { codec.decode_client_key_shares(contents) }
      attempt { codec.decode_server_key_share(contents) }
      attempt { codec.decode_selected_group(contents) }
      attempt { codec.decode_psk_modes(contents) }
      attempt { codec.decode_protocol_names(contents) }
      attempt { codec.decode_cookie(contents) }
      attempt { codec.decode_record_size_limit(contents) }
      attempt { codec.decode_client_pre_shared_key(contents) }
      attempt { codec.decode_selected_identity(contents) }
    end
  end

  private def self.attempt(&) : Nil
    yield
  rescue Beryl::Error
  end

  # Seals *list_of_messages* under the server handshake key the client of
  # *recording* derives from its recorded ServerHello.
  def self.seal_server_flight(recording : Recording, client_hello : Bytes, server_hello : Bytes, list_of_messages : Array(Bytes)) : Bytes?
    hello = TLS::Messages::ServerHello.decode(TLS::Messages.unwrap(server_hello)[1])
    return nil if hello.hello_retry_request?
    suite = TLS::CipherSuite.from_value?(hello.cipher_suite) || return
    return nil if hello.has_extension?(TLS::ExtensionType::PreSharedKey)
    share = TLS::Messages::ExtensionCodec.decode_server_key_share(hello.extension(TLS::ExtensionType::KeyShare) || return)
    secret = recording.client_x25519_secret || return
    return nil unless share.group_value == TLS::NamedGroup::X25519.value
    shared_secret = TLS::X25519Exchange.new(Beryl::Crypto::V1::X25519::PrivateKey.new(secret)).shared_secret(share.key_exchange)
    hash = suite.hash_algorithm
    schedule = TLS::KeySchedule.new(hash)
    schedule.enter_handshake_stage(shared_secret)
    transcript = TLS::TranscriptHash.new
    transcript.add(client_hello)
    transcript.add(server_hello)
    protection = TLS::RecordProtection.new(suite, schedule.server_handshake_traffic_secret(transcript.digest(hash)))
    io = IO::Memory.new
    list_of_messages.each do |message|
      offset = 0
      while offset < message.size || offset == 0
        fragment = message[offset, Math.min(16_384, message.size - offset)]
        io.write(protection.seal(TLS::ContentType::Handshake, fragment))
        offset += fragment.size
        break if fragment.empty?
      end
    end
    io.to_slice
  end

  def self.run(iterations : Int64, seed : UInt64) : Nil
    generator = Random::PCG32.new(seed)
    corpus = build_corpus
    list_of_messages = corpus.flat_map(&.list_of_messages)
    (3..7).each do |section|
      Rfc8448Trace.section(section).each do |step|
        if message_match = step.title.match(/\Aconstruct an? (\w+) handshake message\z/)
          list_of_messages << step.field(message_match[1])
        end
      end
    end
    server_context = @@server_context || raise "no server context"
    STDOUT.puts "fuzz: #{iterations} iterations, seed #{seed}, #{corpus.size} recorded handshakes, #{list_of_messages.size} messages"
    started_at = Time.instant

    iterations.times do |iteration|
      donor = list_of_messages.sample(generator)

      message = mutant(list_of_messages.sample(generator), donor, generator)
      exercise("decoders", message) { decode_everything(message) }

      recording = corpus.sample(generator)
      client_records = records_of(recording.client_to_server.to_slice)
      plaintext_client = client_records.select { |record_bytes| record_bytes[0] == TLS::ContentType::Handshake.value }
      unless plaintext_client.empty?
        script = IO::Memory.new
        index_to_mutate = generator.rand(plaintext_client.size)
        plaintext_client.each_with_index do |record_bytes, index|
          script.write(index == index_to_mutate ? mutant(record_bytes, donor, generator) : record_bytes)
        end
        input = script.to_slice
        exercise("server", input) do
          TLS::ServerHandshake.new(TLS::RecordLayer.new(TlsHarness::ScriptedIO.new(input)), server_context).perform
        end
      end

      server_records = records_of(recording.server_to_client.to_slice)
      plaintext_server = server_records.select { |record_bytes| record_bytes[0] == TLS::ContentType::Handshake.value }
      unless plaintext_server.empty?
        script = IO::Memory.new
        index_to_mutate = generator.rand(plaintext_server.size)
        server_records.each do |record_bytes|
          if record_bytes[0] == TLS::ContentType::Handshake.value && plaintext_server.index(record_bytes) == index_to_mutate
            script.write(mutant(record_bytes, donor, generator))
          else
            script.write(record_bytes)
          end
        end
        input = script.to_slice
        exercise("client hello", input) do
          TLS::ClientHandshake.new(TLS::RecordLayer.new(TlsHarness::ScriptedIO.new(input)), recording.replay_context, "localhost").perform
        end
      end

      messages = recording.list_of_messages
      client_hello = messages.find { |candidate| candidate[0] == TLS::HandshakeType::ClientHello.value }
      server_hello = messages.find { |candidate| candidate[0] == TLS::HandshakeType::ServerHello.value }
      flight = messages.select { |candidate| {8_u8, 11_u8, 15_u8, 20_u8}.includes?(candidate[0]) }
      flight = flight[0, 4]
      if client_hello && server_hello && flight.size == 4 && client_records.size >= 1
        index_to_mutate = generator.rand(flight.size)
        mutated_flight = flight.map_with_index { |candidate, index| index == index_to_mutate ? mutant(candidate, donor, generator) : candidate }
        if sealed = seal_server_flight(recording, client_hello, server_hello, mutated_flight)
          server_hello_record = server_records.first
          input = server_hello_record + sealed
          exercise("client flight", input) do
            TLS::ClientHandshake.new(TLS::RecordLayer.new(TlsHarness::ScriptedIO.new(input)), recording.replay_context, "localhost").perform
          end
        end
      end

      if (iteration + 1) % 100_000 == 0
        STDOUT.puts "fuzz: #{iteration + 1} iterations, #{@@finding_count} findings, #{(Time.instant - started_at).total_seconds.round(1)} s"
        STDOUT.flush
      end
    end
    @@outcome_counts.keys.sort.each { |key| STDOUT.puts "  #{key}: #{@@outcome_counts[key]}" }
    STDOUT.puts "fuzz: #{iterations} iterations (4 targets each) in #{(Time.instant - started_at).total_seconds.round(1)} s, #{@@finding_count} findings, #{@@pause_count} one-off pauses"
  end
end

iterations = ARGV[0]?.try(&.to_i64) || 10_000_i64
seed = ARGV[1]?.try(&.to_u64) || Random::Secure.rand(UInt64)
TlsHandshakeFuzz.run(iterations, seed)
exit(TlsHandshakeFuzz.finding_count == 0 ? 0 : 1)
