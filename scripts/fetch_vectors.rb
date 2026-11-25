#!/usr/bin/ruby
# frozen_string_literal: true

# Downloads the published test vectors that Beryl's specs read, and checks
# every byte against the sha256 pins in spec/vectors/manifest.json.
#
#   /usr/bin/ruby scripts/fetch_vectors.rb                  install pinned files
#   /usr/bin/ruby scripts/fetch_vectors.rb --print-observed show observed sha256 values
#   /usr/bin/ruby scripts/fetch_vectors.rb --missing        install only downloads with a file absent
#
# Some Wycheproof files (x25519_test.json, ecdh_secp256r1_ecpoint_test.json
# and the RSA files listed in .gitignore) are kept out of the repository:
# their private-key fields are public test data, but they match the commit
# secret scan. CI installs them with
# `--missing`; their sha256 pins in the manifest are checked as for any other.
#
# A download or an extracted file whose sha256 differs from its pin stops the
# run with exit status 1 and leaves spec/vectors untouched for that download.
# `--print-observed` installs nothing; a maintainer uses it to review new pins
# before editing the manifest by hand.
#
# An entry of kind "generated" is a fixture made by a script in this
# repository (its "url" names the script) and committed; it is not
# downloaded, and the spec suite checks its sha256 like any other file.

require "digest"
require "fileutils"
require "json"
require "net/http"
require "open3"
require "tmpdir"
require "uri"

REPOSITORY_ROOT = File.expand_path("..", __dir__)
VECTOR_ROOT = File.join(REPOSITORY_ROOT, "spec", "vectors")
MANIFEST_PATH = File.join(VECTOR_ROOT, "manifest.json")
SOURCES_PATH = File.join(VECTOR_ROOT, "SOURCES.md")
USER_AGENT = "AgentC-Consulting-research/1.0 (+https://agentc.consulting; agent_c@agentc.consulting)"
MAXIMUM_REDIRECTS = 3

class PinMismatch < StandardError; end

def download(url, redirects_left = MAXIMUM_REDIRECTS)
  uri = URI(url)
  raise ArgumentError, "only https downloads are accepted: #{url}" unless uri.scheme == "https"

  response = Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
    http.get(uri.request_uri, "User-Agent" => USER_AGENT)
  end
  if response.is_a?(Net::HTTPRedirection) && redirects_left.positive?
    return download(URI.join(url, response["location"]).to_s, redirects_left - 1)
  end
  raise "download failed with HTTP #{response.code}: #{url}" unless response.is_a?(Net::HTTPSuccess)

  response.body
end

def sha256_of(bytes)
  Digest::SHA256.hexdigest(bytes)
end

def check_pin(label, bytes, pinned_sha256)
  observed = sha256_of(bytes)
  return if observed == pinned_sha256

  raise PinMismatch, "#{label}: sha256 is #{observed}, the manifest pins #{pinned_sha256}"
end

# Returns {stored_path => bytes} for one manifest download entry. The download
# and any extraction happen in a new, empty temporary directory.
def collect_files(download_entry)
  body = download(download_entry.fetch("url"))
  files = {}
  Dir.mktmpdir("beryl-vectors-") do |work_directory|
    if download_entry.fetch("kind") == "zip"
      archive_path = File.join(work_directory, "archive.zip")
      File.binwrite(archive_path, body)
      extraction_directory = File.join(work_directory, "extracted")
      Dir.mkdir(extraction_directory)
      _output, status = Open3.capture2e("/usr/bin/unzip", "-q", archive_path, "-d", extraction_directory)
      raise "unzip failed for #{download_entry.fetch("url")}" unless status.success?

      download_entry.fetch("list_of_files").each do |file_entry|
        extracted_path = File.expand_path(file_entry.fetch("archive_path"), extraction_directory)
        unless extracted_path.start_with?(extraction_directory + File::SEPARATOR)
          raise "archive path leaves the extraction directory: #{file_entry.fetch("archive_path")}"
        end
        files[file_entry.fetch("stored_path")] = File.binread(extracted_path)
      end
    else
      files[download_entry.fetch("list_of_files").first.fetch("stored_path")] = body
    end
  end
  [body, files]
end

def downloaded?(download_entry)
  download_entry.fetch("kind") != "generated"
end

def print_observed(manifest)
  manifest.fetch("list_of_downloads").select { |entry| downloaded?(entry) }.each do |download_entry|
    body, files = collect_files(download_entry)
    puts "#{sha256_of(body)}  #{download_entry.fetch("url")}"
    files.each { |stored_path, bytes| puts "  #{sha256_of(bytes)}  #{stored_path}" }
  end
end

def install(manifest, only_missing: false)
  manifest.fetch("list_of_downloads").select { |entry| downloaded?(entry) }.each do |download_entry|
    if only_missing && download_entry.fetch("list_of_files").all? { |file_entry| File.exist?(File.join(VECTOR_ROOT, file_entry.fetch("stored_path"))) }
      next
    end

    body, files = collect_files(download_entry)
    check_pin(download_entry.fetch("url"), body, download_entry.fetch("sha256"))
    download_entry.fetch("list_of_files").each do |file_entry|
      stored_path = file_entry.fetch("stored_path")
      check_pin(stored_path, files.fetch(stored_path), file_entry.fetch("sha256"))
    end
    files.each do |stored_path, bytes|
      destination = File.expand_path(stored_path, VECTOR_ROOT)
      raise "stored path leaves spec/vectors: #{stored_path}" unless destination.start_with?(VECTOR_ROOT + File::SEPARATOR)

      FileUtils.mkdir_p(File.dirname(destination))
      File.binwrite(destination, bytes)
    end
    puts "verified #{files.size} file(s) from #{download_entry.fetch("url")}"
  end
end

def write_sources(manifest)
  lines = [
    "# Test vector sources",
    "",
    "Generated by `scripts/fetch_vectors.rb` from `spec/vectors/manifest.json`; edit the manifest, then run the script.",
    "The spec suite checks each file's sha256 against the manifest before reading it and fails, naming the file, when they differ.",
    "",
  ]
  manifest.fetch("list_of_downloads").group_by { |entry| entry.fetch("source") }.each do |source, list_of_entries|
    lines << "## #{source}"
    lines << ""
    lines << "License: #{list_of_entries.first.fetch("license")}"
    lines << ""
    list_of_entries.each do |download_entry|
      if downloaded?(download_entry)
        lines << "- Download: #{download_entry.fetch("url")}"
        lines << "  - Pinned at: #{download_entry.fetch("pinned_at")}"
        lines << "  - Download sha256: `#{download_entry.fetch("sha256")}`"
      else
        lines << "- Generated by: #{download_entry.fetch("url")}"
        lines << "  - Pinned at: #{download_entry.fetch("pinned_at")}"
        lines << "  - Generated file sha256: `#{download_entry.fetch("sha256")}`"
      end
      download_entry.fetch("list_of_files").each do |file_entry|
        lines << "  - `spec/vectors/#{file_entry.fetch("stored_path")}` sha256 `#{file_entry.fetch("sha256")}`"
      end
    end
    lines << ""
  end
  File.write(SOURCES_PATH, lines.join("\n"))
end

manifest = JSON.parse(File.read(MANIFEST_PATH))
begin
  if ARGV.include?("--print-observed")
    print_observed(manifest)
  else
    install(manifest, only_missing: ARGV.include?("--missing"))
    write_sources(manifest)
  end
rescue PinMismatch => error
  warn "PIN MISMATCH: #{error.message}"
  exit 1
end
