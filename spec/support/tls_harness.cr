require "socket"

# Helpers for the TLS specs: an IO that reads a script and records what is
# written, connected client and server sockets, and fixed randomness.
module TlsHarness
  # Reads from *input* and records every write.
  class ScriptedIO < IO
    getter output = IO::Memory.new

    def initialize(input : Bytes)
      @input = IO::Memory.new(input)
    end

    def read(slice : Bytes) : Int32
      @input.read(slice)
    end

    def write(slice : Bytes) : Nil
      @output.write(slice)
    end
  end

  # Randomness that hands out queued values first, then real ones.
  class FixedRandomness < Beryl::TLS::HandshakeRandomness
    getter list_of_byte_strings = [] of Bytes
    getter list_of_x25519_keys = [] of Beryl::Crypto::V1::X25519::PrivateKey
    getter list_of_p256_keys = [] of Beryl::Crypto::V1::P256::PrivateKey

    def random_bytes(bytesize : Int32) : Bytes
      if queued = @list_of_byte_strings.shift?
        raise "a queued value of #{queued.size} bytes where #{bytesize} were asked for" unless queued.size == bytesize
        return queued
      end
      super
    end

    def generate_x25519_key : Beryl::Crypto::V1::X25519::PrivateKey
      @list_of_x25519_keys.shift? || super
    end

    def generate_p256_key : Beryl::Crypto::V1::P256::PrivateKey
      @list_of_p256_keys.shift? || super
    end
  end

  # One certificate authority for the whole suite.
  class_getter authority : TestCertificateAuthority::Authority { TestCertificateAuthority::Authority.new }

  # A server context with a certificate of *key_kind* from the shared
  # authority.
  def self.server_context(key_kind : TestCertificateAuthority::KeyKind = TestCertificateAuthority::KeyKind::P256) : Beryl::TLS::Context::Server
    context = Beryl::TLS::Context::Server.new
    context.certified_key = authority.issue(key_kind)
    context
  end

  # A client context that trusts the shared authority.
  def self.client_context : Beryl::TLS::Context::Client
    context = Beryl::TLS::Context::Client.new
    context.trust_store = authority.trust_store
    context
  end

  # Runs a handshake over a socket pair: the server in a fiber, the client
  # here. Yields the client socket and the server's result (the socket or
  # the error it raised) once both handshakes ended.
  def self.connect(server_context : Beryl::TLS::Context::Server, client_context : Beryl::TLS::Context::Client,
                   hostname : String? = "localhost", &)
    client_io, server_io = UNIXSocket.pair
    server_result = Channel(Beryl::TLS::Socket::Server | Exception).new(1)
    spawn do
      server_result.send(Beryl::TLS::Socket::Server.new(server_io, server_context, sync_close: true))
    rescue error
      server_io.close
      server_result.send(error)
    end
    client = begin
      Beryl::TLS::Socket::Client.new(client_io, client_context, sync_close: true, hostname: hostname)
    rescue error
      client_io.close
      error
    end
    server = server_result.receive
    begin
      yield client, server
    ensure
      client.close if client.is_a?(Beryl::TLS::Socket::Client) && !client.closed?
      server.close if server.is_a?(Beryl::TLS::Socket::Server) && !server.closed?
    end
  end
end
