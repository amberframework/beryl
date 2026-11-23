#!/usr/bin/ruby
# frozen_string_literal: true

# Builds the real-world certificate corpus for the certificate differential
# and the fuzz campaign: a contiguous range of entries from Cloudflare's
# Nimbus2026 Certificate Transparency log (RFC 6962 get-entries), each with
# the chain its submitter logged, written to
# spec/vectors/corpus/ct-nimbus2026.bin and checked against the sha256 pin
# below. The file is kept out of git for its size.
#
#   /usr/bin/ruby scripts/fetch_certificate_corpus.rb             install, checked by sha256
#   /usr/bin/ruby scripts/fetch_certificate_corpus.rb --print     build, install unchecked and print its sha256 (for a new pin)
#
# File format, all integers big-endian: the 8 bytes "BERYLCT1", then one
# record per log entry: entry type (1 byte: 0 for an X.509 entry, 1 for a
# precertificate), the log timestamp in milliseconds (8 bytes), the number
# of certificates (2 bytes), then each certificate as a 4-byte length and
# its DER, the logged certificate first and its chain after it.
#
# Log entries hold certificates as issued, so the corpus is untrusted data:
# nothing in it is run, and the specs only parse it.

require "base64"
require "digest"
require "fileutils"
require "json"
require "net/http"
require "uri"

LOG_URL = "https://ct.cloudflare.com/logs/nimbus2026/ct/v1/get-entries"
FIRST_INDEX = 6_800_000_000
BATCH_SIZE = 256
BATCH_COUNT = 160
PINNED_SHA256 = "e3f14969b8a9ce9da45da21db9d01728c2e8435196f377b11fd6afe181555888"
USER_AGENT = "AgentC-Consulting-research/1.0 (+https://agentc.consulting; agent_c@agentc.consulting)"
OUTPUT_PATH = File.expand_path("../spec/vectors/corpus/ct-nimbus2026.bin", __dir__)

def get_entries(start, finish)
  uri = URI("#{LOG_URL}?start=#{start}&end=#{finish}")
  3.times do |attempt|
    response = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 20, read_timeout: 60) do |http|
      http.get(uri.request_uri, "User-Agent" => USER_AGENT)
    end
    return JSON.parse(response.body).fetch("entries") if response.is_a?(Net::HTTPSuccess)

    warn "HTTP #{response.code} for #{start}..#{finish}, attempt #{attempt + 1}"
    sleep(2 * (attempt + 1))
  end
  raise "get-entries failed for #{start}..#{finish}"
end

def read_u24(bytes, offset)
  (bytes.getbyte(offset) << 16) | (bytes.getbyte(offset + 1) << 8) | bytes.getbyte(offset + 2)
end

# A list of u24-length-prefixed certificates inside a u24-length vector.
def read_certificate_list(bytes, offset)
  total = read_u24(bytes, offset)
  position = offset + 3
  finish = position + total
  list = []
  while position < finish
    length = read_u24(bytes, position)
    list << bytes.byteslice(position + 3, length)
    position += 3 + length
  end
  [list, finish]
end

def record_for(entry)
  leaf_input = Base64.strict_decode64(entry.fetch("leaf_input"))
  extra_data = Base64.strict_decode64(entry.fetch("extra_data"))
  timestamp = leaf_input.byteslice(2, 8).unpack1("Q>")
  entry_type = leaf_input.byteslice(10, 2).unpack1("n")
  if entry_type.zero?
    certificate_length = read_u24(leaf_input, 12)
    leaf = leaf_input.byteslice(15, certificate_length)
    chain, = read_certificate_list(extra_data, 0)
  else
    precertificate_length = read_u24(extra_data, 0)
    leaf = extra_data.byteslice(3, precertificate_length)
    chain, = read_certificate_list(extra_data, 3 + precertificate_length)
  end
  certificates = [leaf] + chain
  [entry_type, timestamp, certificates.size].pack("CQ>n") +
    certificates.map { |der| [der.bytesize].pack("N") + der }.join
end

def build_corpus
  output = +"BERYLCT1"
  output.force_encoding(Encoding::BINARY)
  BATCH_COUNT.times do |batch|
    start = FIRST_INDEX + batch * BATCH_SIZE
    entries = get_entries(start, start + BATCH_SIZE - 1)
    raise "short batch at #{start}: #{entries.size} entries" unless entries.size == BATCH_SIZE

    entries.each { |entry| output << record_for(entry) }
    sleep(0.2)
  end
  output
end

corpus = build_corpus
observed = Digest::SHA256.hexdigest(corpus)
if ARGV.include?("--print")
  FileUtils.mkdir_p(File.dirname(OUTPUT_PATH))
  File.binwrite(OUTPUT_PATH, corpus)
  puts "#{observed}  #{BATCH_COUNT * BATCH_SIZE} entries from #{FIRST_INDEX}, #{corpus.bytesize} bytes"
  exit 0
end
unless observed == PINNED_SHA256
  warn "the corpus has sha256 #{observed}; the script pins #{PINNED_SHA256}"
  exit 1
end
FileUtils.mkdir_p(File.dirname(OUTPUT_PATH))
File.binwrite(OUTPUT_PATH, corpus)
puts "verified #{BATCH_COUNT * BATCH_SIZE} entries, #{corpus.bytesize} bytes, sha256 #{observed}"
