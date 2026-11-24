require "socket"
require "../../src/beryl"

# BoringSSL's TLS test runner (BoGo) drives this shim, which plays one side
# of a connection with Beryl while the runner's Go TLS plays the other:
#
#     crystal-alpha build --release spec/bogo/beryl_bogo_shim.cr -o beryl_bogo_shim
#     cd boringssl/ssl/test/runner && go test -shim-path /path/beryl_bogo_shim \
#       -shim-config /path/spec/bogo/config.json -allow-unimplemented -loose-errors
#
# The shim speaks the runner's protocol: it connects to `-port`, sends
# `-shim-id` as eight little-endian bytes, runs the handshake, checks the
# `-expect-*` flags, then echoes every byte it reads back XOR 0xff until
# the runner closes. `-resume-count N` makes N more connections that
# resume the first one's session. A flag this shim does not know, or one
# that asks for something Beryl does not do (TLS 1.2, DTLS, QUIC, 0-RTT,
# client certificates), exits 89, which the runner counts as
# unimplemented. `spec/bogo/config.json` lists every disabled test with
# its reason; `docs/tls.md` describes a run.
module BerylBogoShim
  UNIMPLEMENTED_EXIT_STATUS =     89
  TLS13_VERSION             = 0x0304

  # Settings that may differ per connection (`-on-initial-`,
  # `-on-resume-` prefixes).
  class ConnectionSettings
    property list_of_curves = [] of Int32
    property host_name : String? = nil
    property expected_server_name : String? = nil
    property advertised_alpn : Bytes? = nil
    property selected_alpn : String? = nil
    property expected_alpn : String? = nil
    property? is_declining_alpn = false
    property expected_version = 0
    property expected_curve_id = 0
    property? is_expecting_session_miss = false
    property? is_expecting_no_session = false
    property? is_shim_writing_first = false
    property? is_shim_shutting_down = false
    property? is_checking_close_notify = false
    property? is_sending_key_update_after_read = false
    property? is_sending_key_update_before_read = false
    property export_keying_material_bytesize = 0
    property export_label = ""
    property export_context = ""
    property? is_using_export_context = false
    property read_bytesize = 512

    def copy : ConnectionSettings
      copy = dup
      copy.list_of_curves = list_of_curves.dup
      copy.advertised_alpn = advertised_alpn.try(&.dup)
      copy
    end
  end

  # The whole command line, parsed.
  class Configuration
    property port = 0
    property shim_id = 0_u64
    property? is_ipv6 = false
    property? is_server = false
    property certificate_path : String? = nil
    property key_path : String? = nil
    property trust_certificate_path : String? = nil
    property? is_verifying_peer = false
    property resume_count = 0
    property minimum_version = 0
    property maximum_version = 0
    property? is_ticket_disabled = false
    property base = ConnectionSettings.new
    property initial = ConnectionSettings.new
    property resume = ConnectionSettings.new
    property list_of_prefixed_arguments = [] of {String, String, String?}
  end

  # Raised for a flag or a combination this shim leaves to the runner as
  # unimplemented.
  class Unimplemented < Exception
  end

  # Raised when a connection's outcome differs from an `-expect-*` flag.
  class ExpectationFailed < Exception
  end

  # Flags the shim accepts that change nothing for Beryl: `-async` and
  # `-implicit-handshake` only change how BoringSSL's own shim drives its
  # API (Beryl's sockets block and run the handshake when made), and the
  # `-no-tls1*` flags turn off versions Beryl never speaks.
  NEUTRAL_FLAGS = ["-async", "-implicit-handshake", "-no-tls1", "-no-tls11", "-no-tls12", "-no-ssl3"]

  # Flags with a parameter that apply per connection.
  PER_CONNECTION_FLAGS_WITH_PARAMETER = [
    "-curves", "-host-name", "-expect-server-name", "-advertise-alpn", "-select-alpn", "-expect-alpn",
    "-expect-version", "-expect-curve-id", "-export-keying-material", "-export-label", "-export-context", "-read-size",
  ]

  # Flags without a parameter that apply per connection.
  PER_CONNECTION_BOOLEAN_FLAGS = [
    "-decline-alpn", "-expect-session-miss", "-expect-no-session", "-shim-writes-first", "-shim-shuts-down",
    "-check-close-notify", "-key-update", "-key-update-before-read", "-use-export-context",
  ]

  def self.parse(list_of_arguments : Array(String)) : Configuration
    configuration = Configuration.new
    index = 0
    while index < list_of_arguments.size
      argument = list_of_arguments[index]
      index += 1
      prefix = nil
      name = argument
      {"-on-initial", "-on-resume"}.each do |candidate|
        if argument.starts_with?(candidate + "-")
          prefix = candidate
          name = argument[candidate.size..]
        end
      end
      raise Unimplemented.new("the -on-retry, -on-shim and -on-handshaker prefixes (0-RTT and split handshakes)") if argument.starts_with?("-on-retry-") || argument.starts_with?("-on-shim-") || argument.starts_with?("-on-handshaker-")

      if PER_CONNECTION_FLAGS_WITH_PARAMETER.includes?(name)
        raise ArgumentError.new("#{argument} needs a parameter") unless index < list_of_arguments.size
        parameter = list_of_arguments[index]
        index += 1
        settings = settings_for(configuration, prefix)
        apply_per_connection_flag(settings, name, parameter)
        configuration.list_of_prefixed_arguments << {prefix || "", name, parameter}
        next
      end
      if PER_CONNECTION_BOOLEAN_FLAGS.includes?(name)
        apply_per_connection_flag(settings_for(configuration, prefix), name, nil)
        configuration.list_of_prefixed_arguments << {prefix || "", name, nil}
        next
      end
      raise Unimplemented.new("#{argument} with a connection prefix") if prefix
      next if NEUTRAL_FLAGS.includes?(name)

      case name
      when "-port"         then configuration.port = list_of_arguments[index].to_i; index += 1
      when "-shim-id"      then configuration.shim_id = list_of_arguments[index].to_u64; index += 1
      when "-ipv6"         then configuration.is_ipv6 = true
      when "-server"       then configuration.is_server = true
      when "-cert-file"    then configuration.certificate_path = list_of_arguments[index]; index += 1
      when "-key-file"     then configuration.key_path = list_of_arguments[index]; index += 1
      when "-trust-cert"   then configuration.trust_certificate_path = list_of_arguments[index]; index += 1
      when "-verify-peer"  then configuration.is_verifying_peer = true
      when "-resume-count" then configuration.resume_count = list_of_arguments[index].to_i; index += 1
      when "-min-version"  then configuration.minimum_version = list_of_arguments[index].to_i; index += 1
      when "-max-version"  then configuration.maximum_version = list_of_arguments[index].to_i; index += 1
      when "-no-ticket"    then configuration.is_ticket_disabled = true
      when "-no-tls13"     then raise Unimplemented.new("-no-tls13: Beryl speaks TLS 1.3 only (TLS 1.2 is milestone B6)")
      else
        raise Unimplemented.new("#{name} is not implemented by this shim")
      end
    end
    configuration.initial = merge(configuration, "-on-initial")
    configuration.resume = merge(configuration, "-on-resume")
    check_supported(configuration)
    configuration
  end

  # Prefixed flags are collected into the base settings' copy for their
  # connection, in command-line order.
  private def self.settings_for(configuration : Configuration, prefix : String?) : ConnectionSettings
    prefix ? ConnectionSettings.new : configuration.base
  end

  private def self.merge(configuration : Configuration, wanted_prefix : String) : ConnectionSettings
    settings = configuration.base.copy
    configuration.list_of_prefixed_arguments.each do |(prefix, name, parameter)|
      apply_per_connection_flag(settings, name, parameter) if prefix == wanted_prefix
    end
    settings
  end

  private def self.apply_per_connection_flag(settings : ConnectionSettings, name : String, parameter : String?) : Nil
    value = parameter || ""
    case name
    when "-curves"                 then settings.list_of_curves << value.to_i
    when "-host-name"              then settings.host_name = value
    when "-expect-server-name"     then settings.expected_server_name = value
    when "-advertise-alpn"         then settings.advertised_alpn = value.to_slice.dup
    when "-select-alpn"            then settings.selected_alpn = value
    when "-expect-alpn"            then settings.expected_alpn = value
    when "-expect-version"         then settings.expected_version = value.to_i
    when "-expect-curve-id"        then settings.expected_curve_id = value.to_i
    when "-export-keying-material" then settings.export_keying_material_bytesize = value.to_i
    when "-export-label"           then settings.export_label = value
    when "-export-context"         then settings.export_context = value
    when "-read-size"              then settings.read_bytesize = value.to_i
    when "-decline-alpn"           then settings.is_declining_alpn = true
    when "-expect-session-miss"    then settings.is_expecting_session_miss = true
    when "-expect-no-session"      then settings.is_expecting_no_session = true
    when "-shim-writes-first"      then settings.is_shim_writing_first = true
    when "-shim-shuts-down"        then settings.is_shim_shutting_down = true
    when "-check-close-notify"     then settings.is_checking_close_notify = true
    when "-key-update"             then settings.is_sending_key_update_after_read = true
    when "-key-update-before-read" then settings.is_sending_key_update_before_read = true
    when "-use-export-context"     then settings.is_using_export_context = true
    end
  end

  private def self.check_supported(configuration : Configuration) : Nil
    maximum = configuration.maximum_version
    if maximum != 0 && maximum < TLS13_VERSION
      raise Unimplemented.new("-max-version #{maximum}: TLS 1.2 and older are milestone B6")
    end
    if configuration.minimum_version > TLS13_VERSION
      raise Unimplemented.new("-min-version #{configuration.minimum_version}")
    end
    if configuration.is_server? && configuration.is_verifying_peer?
      raise Unimplemented.new("-verify-peer on a server: Beryl's server does not request client certificates")
    end
    if !configuration.is_server? && (configuration.certificate_path || configuration.key_path)
      raise Unimplemented.new("a client certificate: Beryl's client answers a CertificateRequest with an empty Certificate")
    end
    if !configuration.is_server? && configuration.is_ticket_disabled?
      raise Unimplemented.new("-no-ticket on a client")
    end
    {configuration.initial, configuration.resume}.each do |settings|
      settings.list_of_curves.each do |curve|
        unless Beryl::TLS::NamedGroup.supported_value?(curve.to_u16)
          raise Unimplemented.new("-curves #{curve}: Beryl offers x25519 (29) and secp256r1 (23)")
        end
      end
      if settings.is_shim_shutting_down? && settings.is_checking_close_notify?
        raise Unimplemented.new("-shim-shuts-down with -check-close-notify: the socket closes its IO after its close_notify")
      end
    end
  end

  # Decodes ALPN's wire form (each name after its length byte).
  def self.decode_alpn(wire : Bytes) : Array(String)
    list = [] of String
    offset = 0
    while offset < wire.size
      length = wire[offset].to_i
      offset += 1
      raise ArgumentError.new("a malformed -advertise-alpn") if length == 0 || offset + length > wire.size
      list << String.new(wire[offset, length])
      offset += length
    end
    list
  end

  def self.list_of_groups(settings : ConnectionSettings) : Array(Beryl::TLS::NamedGroup)?
    return nil if settings.list_of_curves.empty?
    settings.list_of_curves.map { |curve| Beryl::TLS::NamedGroup.from_value(curve.to_u16) }
  end

  def self.build_server_context(configuration : Configuration) : Beryl::TLS::Context::Server
    context = Beryl::TLS::Context::Server.new
    certificate_path = configuration.certificate_path || raise Unimplemented.new("a server with no -cert-file (a PSK or PAKE credential)")
    key_path = configuration.key_path || raise Unimplemented.new("a server with no -key-file")
    begin
      context.certificate_chain = certificate_path
      context.private_key = key_path
      context.certified_key
    rescue error : Beryl::Error
      raise Unimplemented.new("the server credential: #{error.message}")
    end
    context.session_ticket_count = 0 if configuration.is_ticket_disabled?
    context
  end

  def self.build_client_context(configuration : Configuration) : Beryl::TLS::Context::Client
    context = Beryl::TLS::Context::Client.new
    if configuration.is_verifying_peer?
      path = configuration.trust_certificate_path || raise ArgumentError.new("-verify-peer needs -trust-cert")
      context.ca_certificates = path
    else
      context.verify_mode = Beryl::TLS::VerifyMode::None
    end
    context
  end

  # Applies one connection's settings to the shared context.
  def self.configure_server(context : Beryl::TLS::Context::Server, settings : ConnectionSettings) : Nil
    if groups = list_of_groups(settings)
      context.list_of_groups = groups
    end
    selected = settings.selected_alpn
    context.list_of_alpn_protocols = if settings.is_declining_alpn? || selected.nil?
                                       [] of String
                                     else
                                       [selected]
                                     end
  end

  def self.configure_client(context : Beryl::TLS::Context::Client, settings : ConnectionSettings) : Nil
    if groups = list_of_groups(settings)
      context.list_of_groups = groups
      context.list_of_key_share_groups = [groups.first]
    end
    wire = settings.advertised_alpn
    context.list_of_alpn_protocols = wire ? decode_alpn(wire) : [] of String
  end

  def self.connect(configuration : Configuration) : TCPSocket
    host = configuration.is_ipv6? ? "::1" : "127.0.0.1"
    tcp = TCPSocket.new(host, configuration.port)
    tcp.sync = true
    tcp.write_bytes(configuration.shim_id, IO::ByteFormat::LittleEndian)
    tcp
  end

  def self.check_expectations(socket : Beryl::TLS::Socket, settings : ConnectionSettings, is_resume : Bool) : Nil
    if settings.expected_version != 0 && settings.expected_version != TLS13_VERSION
      raise ExpectationFailed.new("want version #{settings.expected_version.to_s(16)}, got 0304")
    end
    expect_resume = is_resume && !settings.is_expecting_session_miss?
    if socket.resumed? != expect_resume
      raise ExpectationFailed.new("session unexpectedly was#{socket.resumed? ? "" : " not"} reused")
    end
    if expected = settings.expected_alpn
      actual = socket.alpn_protocol
      raise ExpectationFailed.new("want ALPN #{expected.inspect}, got #{actual.inspect}") unless actual == expected
    end
    if settings.expected_curve_id != 0
      actual = socket.group.try(&.value.to_i) || 0
      raise ExpectationFailed.new("want curve #{settings.expected_curve_id}, got #{actual}") unless actual == settings.expected_curve_id
    end
    if (expected = settings.expected_server_name) && socket.is_a?(Beryl::TLS::Socket::Server)
      actual = socket.hostname
      raise ExpectationFailed.new("want server name #{expected.inspect}, got #{actual.inspect}") unless actual == expected
    end
  end

  # Runs one connection: handshake, checks, exports, then the echo loop.
  def self.run_connection(configuration : Configuration, context : Beryl::TLS::Context, settings : ConnectionSettings,
                          is_resume : Bool) : Nil
    tcp = connect(configuration)
    begin
      run_tls(tcp, context, settings, is_resume)
    rescue error
      close_after_failure(tcp)
      raise error
    end
    tcp.close
  end

  # Closing a socket with unread input resets the connection, which can
  # reach the runner before the alert it should read; so after a failure
  # the shim stops writing, reads to the end, and then closes.
  private def self.close_after_failure(tcp : TCPSocket) : Nil
    tcp.close_write
    tcp.read_timeout = 2.seconds
    buffer = Bytes.new(4096)
    while tcp.read(buffer) > 0
    end
  rescue IO::Error
  ensure
    tcp.close
  end

  private def self.run_tls(tcp : TCPSocket, context : Beryl::TLS::Context, settings : ConnectionSettings, is_resume : Bool) : Nil
    socket = if context.is_a?(Beryl::TLS::Context::Server)
               configure_server(context, settings)
               Beryl::TLS::Socket::Server.new(tcp, context, sync_close: false)
             elsif context.is_a?(Beryl::TLS::Context::Client)
               configure_client(context, settings)
               Beryl::TLS::Socket::Client.new(tcp, context, sync_close: false,
                 hostname: settings.host_name || "127.0.0.1")
             else
               raise ArgumentError.new("a context that is neither a client nor a server")
             end
    socket.sync = true
    session_count_after_handshake = context.is_a?(Beryl::TLS::Context::Client) ? context.session_cache.size : 0
    check_expectations(socket, settings, is_resume)

    if settings.export_keying_material_bytesize > 0
      export_context = settings.is_using_export_context? ? settings.export_context.to_slice : Bytes.empty
      socket.write(socket.export_keying_material(settings.export_label, export_context, settings.export_keying_material_bytesize))
    end
    socket.write("hello".to_slice) if settings.is_shim_writing_first?

    unless settings.is_shim_shutting_down?
      echo(socket, settings)
    end

    if context.is_a?(Beryl::TLS::Context::Client)
      has_new_session = context.session_cache.size > session_count_after_handshake
      expect_new_session = !settings.is_expecting_no_session? && !settings.is_shim_shutting_down?
      if has_new_session != expect_new_session
        raise ExpectationFailed.new("new session was#{has_new_session ? "" : " not"} cached, but we expected the opposite")
      end
    end
    socket.close
  end

  private def self.echo(socket : Beryl::TLS::Socket, settings : ConnectionSettings) : Nil
    buffer = Bytes.new(settings.read_bytesize)
    loop do
      socket.update_keys if settings.is_sending_key_update_before_read?
      count = begin
        socket.read(buffer)
      rescue error : IO::EOFError
        raise error if settings.is_checking_close_notify?
        0
      end
      break if count == 0
      socket.update_keys if settings.is_sending_key_update_after_read?
      chunk = buffer[0, count]
      chunk.map! { |byte| byte ^ 0xff_u8 }
      socket.write(chunk)
    end
  end

  # The runner keeps no output from a test the shim declines, so when
  # BERYL_BOGO_UNIMPLEMENTED_LOG names a file each reason is appended there
  # (scripts/bogo/run_bogo.rb counts them).
  def self.record_unimplemented_reason(reason : String) : Nil
    path = ENV["BERYL_BOGO_UNIMPLEMENTED_LOG"]?
    return unless path
    File.open(path, "a") { |file| file.print(reason.gsub("\n", " ") + "\n") }
  end

  def self.run(list_of_arguments : Array(String)) : Int32
    if list_of_arguments.includes?("-is-handshaker-supported")
      STDOUT.puts "No"
      return 0
    end
    configuration = parse(list_of_arguments)
    context = configuration.is_server? ? build_server_context(configuration) : build_client_context(configuration)
    (configuration.resume_count + 1).times do |count|
      settings = count == 0 ? configuration.initial : configuration.resume
      run_connection(configuration, context, settings, count > 0)
    end
    0
  rescue error : Unimplemented
    STDERR.puts "unimplemented: #{error.message}"
    record_unimplemented_reason(error.message || "")
    UNIMPLEMENTED_EXIT_STATUS
  rescue error : Beryl::TLS::Error
    STDERR.puts "#{error.class}: #{error.message} (alert #{error.alert_description})"
    1
  rescue error
    STDERR.puts "#{error.class}: #{error.message}"
    1
  end
end

exit BerylBogoShim.run(ARGV)
