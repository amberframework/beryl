# frozen_string_literal: true

require "open3"

# Makes the test certificates the interop matrix and the tlsfuzzer run use,
# with the pinned OpenSSL that scripts/interop/install_tools.rb built: one
# P-256 root and a leaf per key type (p256, rsa, ed25519) for localhost and
# 127.0.0.1. Each leaf gets KIND.key, KIND.pem and KIND-chain.pem (leaf,
# then root) in the directory; the root is ca.pem. Nothing here is kept in
# the repository.
module TestCertificates
  LIST_OF_KEY_KINDS = {
    "p256" => ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"],
    "rsa" => ["-newkey", "rsa:2048"],
    "ed25519" => ["-newkey", "ed25519"],
  }.freeze

  LEAF_EXTENSIONS = <<~EXT
    basicConstraints=critical,CA:FALSE
    keyUsage=critical,digitalSignature
    extendedKeyUsage=serverAuth
    subjectAltName=DNS:localhost,IP:127.0.0.1
    authorityKeyIdentifier=keyid
    subjectKeyIdentifier=hash
  EXT

  def self.generate(openssl, environment, directory)
    run(environment, openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", "ca.key", "-out", "ca.pem", "-days", "30", "-subj", "/CN=Beryl Interop Root",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", chdir: directory)
    File.write(File.join(directory, "leaf.ext"), LEAF_EXTENSIONS)
    LIST_OF_KEY_KINDS.each do |kind, key_arguments|
      run(environment, openssl, "req", *key_arguments, "-nodes", "-keyout", "#{kind}.key", "-out", "#{kind}.csr",
          "-subj", "/CN=localhost", chdir: directory)
      run(environment, openssl, "x509", "-req", "-in", "#{kind}.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
          "-CAcreateserial", "-out", "#{kind}.pem", "-days", "20", "-extfile", "leaf.ext", chdir: directory)
      File.write(File.join(directory, "#{kind}-chain.pem"),
                 File.read(File.join(directory, "#{kind}.pem")) + File.read(File.join(directory, "ca.pem")))
    end
  end

  CLIENT_EXTENSIONS = <<~EXT
    basicConstraints=critical,CA:FALSE
    keyUsage=critical,digitalSignature
    extendedKeyUsage=clientAuth
    authorityKeyIdentifier=keyid
    subjectKeyIdentifier=hash
  EXT

  # The client subject the interop cells look for in the server's answer.
  CLIENT_SUBJECT = "CN=Beryl Interop Client"

  # Makes a P-256 client certificate (extended key usage clientAuth, no
  # subject alternative name) from the root `generate` made in *directory*:
  # client.key, client.pem and client-chain.pem (leaf, then root).
  def self.generate_client(openssl, environment, directory)
    File.write(File.join(directory, "client.ext"), CLIENT_EXTENSIONS)
    run(environment, openssl, "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "client.key",
        "-out", "client.csr", "-subj", "/#{CLIENT_SUBJECT}", chdir: directory)
    run(environment, openssl, "x509", "-req", "-in", "client.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
        "-out", "client.pem", "-days", "20", "-extfile", "client.ext", chdir: directory)
    File.write(File.join(directory, "client-chain.pem"),
               File.read(File.join(directory, "client.pem")) + File.read(File.join(directory, "ca.pem")))
  end

  def self.run(environment, *command, chdir:)
    output, status = Open3.capture2e(environment, *command, chdir: chdir)
    raise "failed (#{status.exitstatus}): #{command.join(" ")}\n#{output}" unless status.success?

    output
  end
end
