#!/usr/bin/ruby
# frozen_string_literal: true

# Refreshes the two data files compiled into Beryl::Certificates and prints
# the sha256 pins to put in the source:
#
#   - src/beryl/certificates/data/public_suffix_list.dat, the Public Suffix
#     List at a publicsuffix/list commit (`PublicSuffixList::SHA256` and
#     `PublicSuffixList::COMMIT`);
#   - src/beryl/certificates/data/mozilla_root_certificates.pem, the
#     Mozilla root set with the Websites trust bit from the CCADB
#     (`TrustStore::MOZILLA_ROOTS_SHA256` and `MOZILLA_ROOTS_RETRIEVED`).
#
#   /usr/bin/ruby scripts/update_certificate_data.rb PSL_COMMIT
#
# A maintainer reviews the diff of both files and the printed pins, then
# edits the constants by hand; the trust store and Public Suffix List specs
# fail until the pins match the files.

require "digest"
require "net/http"
require "uri"

USER_AGENT = "AgentC-Consulting-research/1.0 (+https://agentc.consulting; agent_c@agentc.consulting)"
DATA_ROOT = File.expand_path("../src/beryl/certificates/data", __dir__)
MOZILLA_ROOTS_URL = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites"

def download(url)
  uri = URI(url)
  response = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 20, read_timeout: 60) do |http|
    http.get(uri.request_uri, "User-Agent" => USER_AGENT)
  end
  raise "download failed with HTTP #{response.code}: #{url}" unless response.is_a?(Net::HTTPSuccess)

  response.body
end

commit = ARGV.fetch(0) { abort "usage: update_certificate_data.rb PSL_COMMIT (a full publicsuffix/list commit hash)" }
abort "PSL_COMMIT must be a full 40-character commit hash" unless commit.match?(/\A[0-9a-f]{40}\z/)

suffixes = download("https://raw.githubusercontent.com/publicsuffix/list/#{commit}/public_suffix_list.dat")
roots = download(MOZILLA_ROOTS_URL).gsub("\r\n", "\n")
abort "the CCADB report holds no certificates" unless roots.include?("-----BEGIN CERTIFICATE-----")

File.binwrite(File.join(DATA_ROOT, "public_suffix_list.dat"), suffixes)
File.binwrite(File.join(DATA_ROOT, "mozilla_root_certificates.pem"), roots)
puts "PublicSuffixList::COMMIT = #{commit.inspect}"
puts "PublicSuffixList::SHA256 = #{Digest::SHA256.hexdigest(suffixes).inspect}"
puts "TrustStore::MOZILLA_ROOTS_SHA256 = #{Digest::SHA256.hexdigest(roots).inspect} (#{roots.scan('BEGIN CERTIFICATE').size} roots)"
puts "TrustStore::MOZILLA_ROOTS_RETRIEVED = #{Time.now.utc.strftime('%Y-%m-%d').inspect}"
