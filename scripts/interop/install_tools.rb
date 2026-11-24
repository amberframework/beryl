#!/usr/bin/ruby
# frozen_string_literal: true

# Installs the interop matrix's peers into PREFIX, each at an exact version
# checked by sha256 before it is unpacked (scripts/interop/TOOLS.md):
#
#   /usr/bin/ruby scripts/interop/install_tools.rb PREFIX [--only openssl,curl,go]
#
# --only installs the named tools alone: Go for the BoGo run
# (scripts/bogo/run_bogo.rb), OpenSSL for tlsfuzzer's certificates
# (scripts/tlsfuzzer/run_tlsfuzzer.rb). curl needs OpenSSL.
#
# OpenSSL and curl are built from their release tarballs (curl against that
# OpenSSL); Go is the release archive. A download whose sha256 differs from
# its pin stops the run with exit status 1 before anything is built.
# Prints the three tools' paths and versions at the end.

require "digest"
require "etc"
require "fileutils"
require "net/http"
require "open3"
require "rbconfig"
require "uri"

USER_AGENT = "AgentC-Consulting-research/1.0 (+https://agentc.consulting; agent_c@agentc.consulting)"

OPENSSL = {
  version: "4.1.0",
  url: "https://github.com/openssl/openssl/releases/download/openssl-4.1.0/openssl-4.1.0.tar.gz",
  sha256: "50c17baf54cb008f6ce42d50deb4b28050a1aad711636cabd4b241c7e90cc2fd",
}.freeze
CURL = {
  version: "8.23.0",
  url: "https://curl.se/download/curl-8.23.0.tar.xz",
  sha256: "8dadd7d2536a314f982ad05a651b713f426bf7d02cc2c76cffb9796f2218e6c5",
}.freeze
GO = {
  version: "1.27.4",
  "linux-amd64" => { url: "https://go.dev/dl/go1.27.4.linux-amd64.tar.gz", sha256: "7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840" },
  "linux-arm64" => { url: "https://go.dev/dl/go1.27.4.linux-arm64.tar.gz", sha256: "3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92" },
  "darwin-arm64" => { url: "https://go.dev/dl/go1.27.4.darwin-arm64.tar.gz", sha256: "91a44a2b8a716600ad94a4f143e156116620db8828086a6e3602291be9bd0bb4" },
}.freeze

def download(url, redirects_left = 5)
  uri = URI(url)
  raise "only https downloads are accepted: #{url}" unless uri.scheme == "https"

  response = Net::HTTP.start(uri.host, uri.port, use_ssl: true) { |http| http.get(uri.request_uri, "User-Agent" => USER_AGENT) }
  if response.is_a?(Net::HTTPRedirection) && redirects_left.positive?
    return download(URI.join(url, response["location"]).to_s, redirects_left - 1)
  end
  raise "download failed with HTTP #{response.code}: #{url}" unless response.is_a?(Net::HTTPSuccess)

  response.body
end

def fetch_checked(url, pinned_sha256, destination)
  bytes = download(url)
  observed = Digest::SHA256.hexdigest(bytes)
  unless observed == pinned_sha256
    warn "sha256 mismatch for #{url}: pinned #{pinned_sha256}, observed #{observed}"
    exit 1
  end
  File.binwrite(destination, bytes)
  puts "verified #{File.basename(destination)} sha256 #{observed}"
end

def run(*command, chdir:)
  output, status = Open3.capture2e(*command, chdir: chdir)
  unless status.success?
    warn output.lines.last(40).join
    warn "failed: #{command.join(" ")}"
    exit 1
  end
end

prefix = File.expand_path(ARGV[0] || abort("usage: install_tools.rb PREFIX [--only openssl,curl,go]"))
only_index = ARGV.index("--only")
list_of_wanted = only_index ? ARGV.fetch(only_index + 1).split(",") : %w(openssl curl go)
list_of_wanted |= ["openssl"] if list_of_wanted.include?("curl")
work = File.join(prefix, "build")
FileUtils.mkdir_p(work)
processor_count = Etc.nprocessors

openssl_prefix = File.join(prefix, "openssl")
if list_of_wanted.include?("openssl") && !File.exist?(File.join(openssl_prefix, "ssl", "openssl.cnf"))
  archive = File.join(work, "openssl.tar.gz")
  fetch_checked(OPENSSL[:url], OPENSSL[:sha256], archive)
  run("tar", "xzf", archive, chdir: work)
  source = File.join(work, "openssl-#{OPENSSL[:version]}")
  run("./config", "--prefix=#{openssl_prefix}", "--libdir=lib", "no-docs", "no-tests", chdir: source)
  run("make", "-j#{processor_count}", chdir: source)
  run("make", "install_sw", "install_ssldirs", chdir: source)
end

curl_prefix = File.join(prefix, "curl")
if list_of_wanted.include?("curl") && !File.exist?(File.join(curl_prefix, "bin", "curl"))
  archive = File.join(work, "curl.tar.xz")
  fetch_checked(CURL[:url], CURL[:sha256], archive)
  run("tar", "xJf", archive, chdir: work)
  source = File.join(work, "curl-#{CURL[:version]}")
  run("./configure", "--prefix=#{curl_prefix}", "--with-openssl=#{openssl_prefix}", "--without-libpsl",
      "--without-brotli", "--without-zstd", "--without-libidn2", "--without-nghttp2", "--without-libssh2",
      "--disable-ldap", "--disable-docs", "--disable-manual",
      "LDFLAGS=-Wl,-rpath,#{openssl_prefix}/lib", chdir: source)
  run("make", "-j#{processor_count}", chdir: source)
  run("make", "install", chdir: source)
end

go_root = File.join(prefix, "go")
if list_of_wanted.include?("go") && !File.exist?(File.join(go_root, "bin", "go"))
  host_os = RbConfig::CONFIG["host_os"].include?("darwin") ? "darwin" : "linux"
  host_cpu = RbConfig::CONFIG["host_cpu"].match?(/arm64|aarch64/) ? "arm64" : "amd64"
  release = GO["#{host_os}-#{host_cpu}"] || abort("no Go pin for #{host_os}-#{host_cpu}")
  archive = File.join(work, "go.tar.gz")
  fetch_checked(release[:url], release[:sha256], archive)
  run("tar", "xzf", archive, chdir: prefix)
end

FileUtils.rm_rf(work)
environment = { "LD_LIBRARY_PATH" => File.join(openssl_prefix, "lib"), "DYLD_LIBRARY_PATH" => File.join(openssl_prefix, "lib") }
tools = [["openssl", File.join(openssl_prefix, "bin", "openssl"), "version"], ["curl", File.join(curl_prefix, "bin", "curl"), "--version"],
         ["go", File.join(go_root, "bin", "go"), "version"]]
tools = tools.select { |(name, _, _)| list_of_wanted.include?(name) }
tools.each do |(name, path, flag)|
  output, = Open3.capture2e(environment, path, flag)
  puts "#{name}: #{path}: #{output.lines.first&.strip}"
end
