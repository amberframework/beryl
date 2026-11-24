#!/usr/bin/ruby
# frozen_string_literal: true

# Runs BoringSSL's TLS test suite (BoGo) against Beryl through
# spec/bogo/beryl_bogo_shim.cr:
#
#   /usr/bin/ruby scripts/bogo/run_bogo.rb WORK [--crystal crystal-alpha] [--workers N] [--report bogo-report.md] [--test PATTERN]
#
# 1. Fetches BoringSSL at the pinned commit below. A commit hash names its
#    whole tree, so `git rev-parse HEAD` equal to the pin is the hash check.
# 2. Installs Go 1.27.4 through scripts/interop/install_tools.rb (sha256
#    checked). The runner's own Go modules are checked by its go.sum.
# 3. Builds the shim in release mode and the runner as a test binary.
# 4. Runs every test with -allow-unimplemented and -loose-errors, under
#    spec/bogo/config.json, whose DisabledTests list every skip with its
#    reason.
# 5. Prints the counts (passed, failed, unimplemented, disabled) and every
#    failing test, and exits 1 when any test fails.
#
# "Unimplemented" is a test the shim declined with exit status 89 because
# it asks for something Beryl does not do (the shim prints which flag).

require "fileutils"
require "json"
require "open3"
require "optparse"

BORINGSSL_REPOSITORY = "https://github.com/google/boringssl.git"
BORINGSSL_COMMIT = "e594e5d509a46fc4f0709c6fc2dac9dd6fce0fd8"
REPOSITORY_ROOT = File.expand_path("../..", __dir__)

options = { crystal: "crystal-alpha", workers: nil, report: nil, test: nil }
OptionParser.new do |parser|
  parser.on("--crystal COMMAND", "Crystal compiler (crystal-alpha)") { |value| options[:crystal] = value }
  parser.on("--workers N", Integer, "runner workers (default: the runner's own, one per processor)") { |value| options[:workers] = value }
  parser.on("--report PATH", "write a Markdown summary") { |value| options[:report] = value }
  parser.on("--test PATTERN", "run only the tests matching these semicolon-separated globs") { |value| options[:test] = value }
end.parse!
work = File.expand_path(ARGV[0] || abort("usage: run_bogo.rb WORK [options]"))
FileUtils.mkdir_p(work)

def run_checked(*command, chdir: Dir.pwd, environment: {})
  output, status = Open3.capture2e(environment, *command, chdir: chdir)
  unless status.success?
    warn output.lines.last(60).join
    abort "failed: #{command.join(" ")}"
  end
  output
end

# 1. BoringSSL at the pinned commit.
boringssl = File.join(work, "boringssl")
unless File.directory?(File.join(boringssl, ".git"))
  FileUtils.mkdir_p(boringssl)
  run_checked("git", "init", "-q", chdir: boringssl)
  run_checked("git", "remote", "add", "origin", BORINGSSL_REPOSITORY, chdir: boringssl)
end
run_checked("git", "fetch", "-q", "--depth", "1", "origin", BORINGSSL_COMMIT, chdir: boringssl)
run_checked("git", "checkout", "-q", "--detach", "FETCH_HEAD", chdir: boringssl)
head = run_checked("git", "rev-parse", "HEAD", chdir: boringssl).strip
abort "BoringSSL is at #{head}, not the pinned #{BORINGSSL_COMMIT}" unless head == BORINGSSL_COMMIT
puts "boringssl: #{head}"

# 2. Go.
tools = File.join(work, "tools")
puts run_checked("/usr/bin/ruby", File.join(REPOSITORY_ROOT, "scripts", "interop", "install_tools.rb"), tools, "--only", "go")
go = File.join(tools, "go", "bin", "go")
go_environment = { "GOTOOLCHAIN" => "local", "GOFLAGS" => "-mod=readonly -modcacherw", "GOPATH" => File.join(work, "gopath"),
                   "GOCACHE" => File.join(work, "gocache") }

# 3. The shim and the runner.
shim = File.join(work, "beryl_bogo_shim")
run_checked(options[:crystal], "build", "--release", "-Dwithout_openssl", File.join("spec", "bogo", "beryl_bogo_shim.cr"),
            "-o", shim, chdir: REPOSITORY_ROOT)
runner_directory = File.join(boringssl, "ssl", "test", "runner")
runner = File.join(work, "bogo_runner")
run_checked(go, "test", "-c", "-o", runner, ".", chdir: runner_directory, environment: go_environment)

# 4. The run.
results_path = File.join(work, "bogo-results.json")
command = [runner, "-test.timeout", "0", "-pipe", "-shim-path", shim,
           "-shim-config", File.join(REPOSITORY_ROOT, "spec", "bogo", "config.json"),
           "-allow-unimplemented", "-loose-errors", "-json-output", results_path]
command += ["-num-workers", options[:workers].to_s] if options[:workers]
command += ["-test", options[:test]] if options[:test]
started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
reasons_path = File.join(work, "unimplemented-reasons.log")
File.write(reasons_path, "")
output, status = Open3.capture2e({ "BERYL_BOGO_UNIMPLEMENTED_LOG" => reasons_path }, *command, chdir: runner_directory)
elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at
File.write(File.join(work, "bogo-runner.log"), output)

# 5. The counts.
unless File.exist?(results_path)
  warn output.lines.last(60).join
  abort "the runner wrote no results (exit #{status.exitstatus})"
end
results = JSON.parse(File.read(results_path))
by_outcome = Hash.new { |hash, key| hash[key] = [] }
results.fetch("tests").each do |name, result|
  by_outcome[result.fetch("actual")] << name
end
disabled = JSON.parse(File.read(File.join(REPOSITORY_ROOT, "spec", "bogo", "config.json"))).fetch("DisabledTests")

# Why each unimplemented test was declined, as the shim recorded it.
reasons = Hash.new(0)
File.foreach(reasons_path) { |line| reasons[line.strip] += 1 }

lines = []
lines << "# BoGo against Beryl"
lines << ""
lines << "BoringSSL #{BORINGSSL_COMMIT}, #{options[:crystal]} release build, #{elapsed.round} s."
lines << ""
lines << "| Outcome | Tests |"
lines << "|---|---|"
%w[PASS FAIL SKIP].each do |outcome|
  label = { "PASS" => "passed", "FAIL" => "failed", "SKIP" => "unimplemented (shim exit 89)" }.fetch(outcome)
  lines << "| #{label} | #{by_outcome[outcome].size} |"
end
(by_outcome.keys - %w[PASS FAIL SKIP]).each { |outcome| lines << "| #{outcome} | #{by_outcome[outcome].size} |" }
lines << "| disabled by config.json (#{disabled.size} patterns, each with its reason) | not run |"
lines << ""
unless by_outcome["FAIL"].empty?
  lines << "## Failed"
  lines << ""
  by_outcome["FAIL"].sort.each { |name| lines << "- #{name}" }
  lines << ""
end
unless reasons.empty?
  lines << "## Why the shim declined (unimplemented), by count"
  lines << ""
  reasons.sort_by { |(reason, count)| [-count, reason] }.each { |(reason, count)| lines << "- #{count}: #{reason}" }
  lines << ""
end
report = lines.join("\n")
File.write(options[:report], report) if options[:report]
puts report
exit(by_outcome["FAIL"].empty? && status.success? ? 0 : 1)
