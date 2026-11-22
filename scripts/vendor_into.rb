#!/usr/bin/ruby
# frozen_string_literal: true

# Places a pinned copy of Beryl inside another library, for a library that
# cannot name the Beryl shard as a dependency.
#
#   /usr/bin/ruby scripts/vendor_into.rb --commit COMMIT --namespace Amber --destination ../amber/src/amber/vendor
#   /usr/bin/ruby scripts/vendor_into.rb --check --destination ../amber/src/amber/vendor
#
# The copy is taken from one commit of this repository with `git archive`,
# so the working tree and any uncommitted edit play no part. Every constant
# moves under the namespace given (`Beryl::Crypto` becomes
# `Amber::Beryl::Crypto`), so that two libraries which each carry a copy can
# be compiled into one program, at different versions if need be.
#
# The destination receives:
#
#   beryl.cr, beryl/**        the source, under the new namespace
#   BERYL_LICENSE             Beryl's license
#   BERYL_VENDORED.json       the commit, the namespace and each file's sha256
#
# `--check` recomputes every sha256 in the manifest and exits 1 on the first
# file that is missing, extra or different. The same check belongs in the
# spec suite of the library that carries the copy.

require "digest"
require "fileutils"
require "json"
require "open3"
require "optparse"
require "rubygems/package"
require "stringio"

REPOSITORY_ROOT = File.expand_path("..", __dir__)
MANIFEST_NAME = "BERYL_VENDORED.json"
LICENSE_NAME = "BERYL_LICENSE"
SOURCE_REPOSITORY = "https://github.com/amberframework/beryl"
NAMESPACE_PATTERN = /\A[A-Z][A-Za-z0-9]*(::[A-Z][A-Za-z0-9]*)*\z/.freeze

def fail_with(message)
  warn "vendor_into: #{message}"
  exit 1
end

def run_git(*arguments)
  output, status = Open3.capture2("git", "-C", REPOSITORY_ROOT, *arguments)
  fail_with("git #{arguments.join(" ")} failed") unless status.success?
  output
end

# Returns {path => contents} for src/beryl.cr, src/beryl/** and LICENSE at
# *commit*, read from the tar stream of `git archive`.
def files_at(commit)
  archive = run_git("archive", "--format=tar", commit, "src/beryl.cr", "src/beryl", "LICENSE")
  files = {}
  Gem::Package::TarReader.new(StringIO.new(archive)) do |tar|
    tar.each { |entry| files[entry.full_name] = entry.read if entry.file? }
  end
  files
end

# Moves every constant of the source under *namespace*.
def under_namespace(source, namespace)
  source
    .gsub(/^module Beryl$/, "module #{namespace}::Beryl")
    .gsub(/(?<![\w:])Beryl::/, "#{namespace}::Beryl::")
end

def sha256_of(bytes)
  Digest::SHA256.hexdigest(bytes)
end

def vendor(commit, namespace, destination)
  full_commit = run_git("rev-parse", "--verify", "#{commit}^{commit}").strip
  files = files_at(full_commit)
  fail_with("commit #{full_commit} holds no src/beryl.cr") unless files.key?("src/beryl.cr")

  FileUtils.rm_rf(File.join(destination, "beryl"))
  FileUtils.rm_f([File.join(destination, "beryl.cr"), File.join(destination, MANIFEST_NAME), File.join(destination, LICENSE_NAME)])
  FileUtils.mkdir_p(destination)

  list_of_files = []
  files.sort.each do |path, contents|
    if path == "LICENSE"
      relative_path = LICENSE_NAME
      written = contents
    else
      relative_path = path.delete_prefix("src/")
      written = under_namespace(contents, namespace)
    end
    target = File.join(destination, relative_path)
    FileUtils.mkdir_p(File.dirname(target))
    File.binwrite(target, written)
    list_of_files << { "path" => relative_path, "sha256" => sha256_of(written), "source_sha256" => sha256_of(contents) }
  end

  manifest = {
    "source" => SOURCE_REPOSITORY,
    "commit" => full_commit,
    "namespace" => "#{namespace}::Beryl",
    "made_by" => "scripts/vendor_into.rb",
    "note" => "A pinned copy. Change Beryl in its own repository, then run the script again; edits made here fail the check.",
    "list_of_files" => list_of_files,
  }
  File.write(File.join(destination, MANIFEST_NAME), JSON.pretty_generate(manifest) + "\n")
  puts "vendored #{list_of_files.size} files from #{full_commit} into #{destination} as #{namespace}::Beryl"
end

def check(destination)
  manifest_path = File.join(destination, MANIFEST_NAME)
  fail_with("#{manifest_path} is missing") unless File.file?(manifest_path)

  manifest = JSON.parse(File.read(manifest_path))
  list_of_paths = manifest.fetch("list_of_files").map { |entry| entry.fetch("path") }
  manifest.fetch("list_of_files").each do |entry|
    target = File.join(destination, entry.fetch("path"))
    fail_with("#{target} is missing") unless File.file?(target)
    observed = sha256_of(File.binread(target))
    next if observed == entry.fetch("sha256")

    fail_with("#{target} does not match its pin: sha256 is #{observed}, the manifest pins #{entry.fetch("sha256")}")
  end

  list_of_present = Dir.glob("beryl/**/*", base: destination).select { |path| File.file?(File.join(destination, path)) }
  list_of_present << "beryl.cr" if File.file?(File.join(destination, "beryl.cr"))
  list_of_extra = list_of_present - list_of_paths
  fail_with("files with no pin: #{list_of_extra.join(", ")}") unless list_of_extra.empty?

  puts "#{list_of_paths.size} files match #{manifest.fetch("commit")} (#{manifest.fetch("namespace")})"
end

options = {}
OptionParser.new do |parser|
  parser.on("--commit COMMIT") { |value| options[:commit] = value }
  parser.on("--namespace NAMESPACE") { |value| options[:namespace] = value }
  parser.on("--destination DIRECTORY") { |value| options[:destination] = value }
  parser.on("--check") { options[:check] = true }
end.parse!

destination = options[:destination] || fail_with("--destination is required")
destination = File.expand_path(destination)

if options[:check]
  check(destination)
else
  commit = options[:commit] || fail_with("--commit is required: the copy is pinned to one commit")
  namespace = options[:namespace] || fail_with("--namespace is required")
  fail_with("#{namespace} is not a constant path such as Amber or Amber::Support") unless namespace.match?(NAMESPACE_PATTERN)
  vendor(commit, namespace, destination)
end
