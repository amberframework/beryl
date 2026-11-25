#!/usr/bin/ruby
# frozen_string_literal: true

# Runs tlsfuzzer's TLS 1.3 scripts against Beryl's example server:
#
#   /usr/bin/ruby scripts/tlsfuzzer/run_tlsfuzzer.rb WORK [--crystal crystal-alpha] [--python python3] [--report tlsfuzzer-report.md]
#
# 1. Fetches tlsfuzzer, tlslite-ng and python-ecdsa at the commits pinned
#    in scripts/tlsfuzzer/config.json; `git rev-parse HEAD` must equal each
#    pin, since a commit hash names its whole tree.
# 2. Builds OpenSSL 4.1.0 (scripts/interop/install_tools.rb, sha256
#    checked) to make the test certificates, and the example server.
# 3. Runs every script the config lists against a fresh server with the
#    listed certificate, running every probe (a script that samples its
#    probes gets -n 0), and reads the script's FAILED list. An entry's
#    server_arguments start the server in another mode (such as asking for
#    client certificates, for the CertificateRequest and CertificateVerify
#    scripts). A failure passes
#    the gate only when it matches one of the script's expected_failures
#    patterns, each of which carries its reason; scripts
#    under not_run are listed in the report with theirs.
# 4. Exits 1 when any failure is unexplained or a script ends without its
#    summary.

require "fileutils"
require "json"
require "open3"
require "optparse"
require "socket"
require "timeout"
require_relative "../interop/test_certificates"

REPOSITORY_ROOT = File.expand_path("../..", __dir__)
CONFIG = JSON.parse(File.read(File.join(__dir__, "config.json")))

options = { crystal: "crystal-alpha", python: "python3", report: nil }
OptionParser.new do |parser|
  parser.on("--crystal COMMAND", "Crystal compiler (crystal-alpha)") { |value| options[:crystal] = value }
  parser.on("--python COMMAND", "Python 3 (python3)") { |value| options[:python] = value }
  parser.on("--report PATH", "write a Markdown summary") { |value| options[:report] = value }
end.parse!
work = File.expand_path(ARGV[0] || abort("usage: run_tlsfuzzer.rb WORK [options]"))
FileUtils.mkdir_p(work)

def run_checked(*command, chdir: Dir.pwd, environment: {})
  output, status = Open3.capture2e(environment, *command, chdir: chdir)
  unless status.success?
    warn output.lines.last(60).join
    abort "failed: #{command.join(" ")}"
  end
  output
end

# 1. The pinned repositories.
CONFIG.fetch("repositories").each do |name, commit|
  directory = File.join(work, name)
  unless File.directory?(File.join(directory, ".git"))
    FileUtils.mkdir_p(directory)
    run_checked("git", "init", "-q", chdir: directory)
    run_checked("git", "remote", "add", "origin", "https://github.com/tlsfuzzer/#{name}.git", chdir: directory)
  end
  run_checked("git", "fetch", "-q", "--depth", "1", "origin", commit, chdir: directory)
  run_checked("git", "checkout", "-q", "--detach", "FETCH_HEAD", chdir: directory)
  head = run_checked("git", "rev-parse", "HEAD", chdir: directory).strip
  abort "#{name} is at #{head}, not the pinned #{commit}" unless head == commit
  puts "#{name}: #{head}"
end
python_path = [File.join(work, "tlsfuzzer"), File.join(work, "tlslite-ng"), File.join(work, "python-ecdsa", "src")].join(":")

# 2. OpenSSL for the certificates, then the example server.
tools = File.join(work, "tools")
puts run_checked("/usr/bin/ruby", File.join(REPOSITORY_ROOT, "scripts", "interop", "install_tools.rb"), tools, "--only", "openssl")
openssl = File.join(tools, "openssl", "bin", "openssl")
openssl_environment = { "LD_LIBRARY_PATH" => File.join(tools, "openssl", "lib"), "DYLD_LIBRARY_PATH" => File.join(tools, "openssl", "lib") }
certificates = File.join(work, "certificates")
FileUtils.mkdir_p(certificates)
TestCertificates.generate(openssl, openssl_environment, certificates)
server = File.join(work, "https_server")
run_checked(options[:crystal], "build", "--release", "-Dwithout_openssl", File.join("examples", "https_server.cr"), "-o", server,
            chdir: REPOSITORY_ROOT)

def start_server(server, certificates, kind, list_of_server_arguments)
  reader, writer = IO.pipe
  pid = Process.spawn(server, "--port", "0", "--certificate-chain", File.join(certificates, "#{kind}-chain.pem"),
                      "--private-key", File.join(certificates, "#{kind}.key"), *list_of_server_arguments,
                      out: writer, err: writer, pgroup: true)
  writer.close
  port = Timeout.timeout(20) do
    loop do
      line = reader.gets or raise "the server exited"
      match = line.match(%r{listening on https://127\.0\.0\.1:(\d+)})
      break match[1].to_i if match
    end
  end
  Thread.new { reader.each_line { |_| } }
  [pid, port]
end

def stop_server(pid)
  Process.kill("TERM", -pid)
  Process.wait(pid)
rescue Errno::ESRCH, Errno::ECHILD
end

# 3. The scripts.
logs = File.join(work, "logs")
FileUtils.mkdir_p(logs)
results = []
CONFIG.fetch("scripts").each do |entry|
  script = entry.fetch("script")
  pid, port = start_server(server, certificates, entry.fetch("certificate"), entry.fetch("server_arguments", []))
  # A script that samples its probes (num_limit) runs every one with -n 0,
  # so each run checks the same probes. Some scripts keep num_limit but do
  # not take -n, so the option string is checked too.
  application = File.join(work, "tlsfuzzer", "tlsfuzzer", "_apps", script.tr("-", "_"))
  application_text = File.exist?(application) ? File.read(application) : ""
  is_sampling = application_text.include?("num_limit") && application_text.match?(/getopt\.getopt\(argv, "[^"]*n:/)
  sampling = is_sampling ? ["-n", "0"] : []
  command = [options[:python], File.join(work, "tlsfuzzer", "scripts", script), "-h", "127.0.0.1", "-p", port.to_s,
             *sampling, *entry.fetch("arguments", [])]
  started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  output, = Open3.capture2e({ "PYTHONPATH" => python_path }, *command, chdir: File.join(work, "tlsfuzzer"))
  elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at
  stop_server(pid)
  File.write(File.join(logs, script.sub(/\.py\z/, ".log")), output)

  counts = {}
  %w(TOTAL SKIP PASS XFAIL FAIL XPASS).each do |label|
    match = output.match(/^#{label}: (\d+)$/)
    counts[label] = match ? match[1].to_i : nil
  end
  failed_section = output[/^FAILED:\n((?:\t.*\n?)*)/, 1] || ""
  list_of_failed = failed_section.lines.map { |line| line.strip.sub(/\A'(.*)'\z/, "\\1") }.reject(&:empty?).uniq
  expected = entry.fetch("expected_failures", {})
  list_of_explained = []
  list_of_unexplained = []
  list_of_failed.each do |name|
    pattern = expected.keys.find { |candidate| Regexp.new(candidate).match?(name) }
    pattern ? list_of_explained << [name, pattern] : list_of_unexplained << name
  end
  is_complete = !counts["TOTAL"].nil?
  results << { script: script, counts: counts, explained: list_of_explained, unexplained: list_of_unexplained,
               is_complete: is_complete, elapsed: elapsed, expected: expected, arguments: entry.fetch("arguments", []),
               arguments_reason: entry["arguments_reason"], server_arguments: entry.fetch("server_arguments", []) }
  status = if !is_complete then "NO SUMMARY"
           elsif list_of_unexplained.empty? then "ok"
           else "FAILED (#{list_of_unexplained.size} unexplained)"
           end
  puts format("%-48s pass %5s  fail %4s  expected %4s  %s", script, counts["PASS"], counts["FAIL"], list_of_explained.size, status)
  list_of_unexplained.first(10).each { |name| puts "    unexplained: #{name}" }
end

# 4. The report.
total_pass = results.sum { |result| result[:counts]["PASS"].to_i }
total_explained = results.sum { |result| result[:explained].size }
total_unexplained = results.sum { |result| result[:unexplained].size }
incomplete = results.reject { |result| result[:is_complete] }
lines = []
lines << "# tlsfuzzer against Beryl"
lines << ""
lines << "tlsfuzzer #{CONFIG["repositories"]["tlsfuzzer"]}, tlslite-ng #{CONFIG["repositories"]["tlslite-ng"]}, " \
         "python-ecdsa #{CONFIG["repositories"]["python-ecdsa"]}; the example server built with #{options[:crystal]} --release."
lines << ""
lines << "#{results.size} scripts run: #{total_pass} probes passed, #{total_explained} failed as expected (each with its reason), " \
         "#{total_unexplained} failed without an explanation, #{incomplete.size} scripts ended without a summary. " \
         "#{CONFIG["not_run"].size} scripts not run, each with its reason."
lines << ""
lines << "| Script | Passed | Failed as expected | Unexplained | Seconds |"
lines << "|---|---|---|---|---|"
results.each do |result|
  server_mode = result[:server_arguments].empty? ? "" : " (server `#{result[:server_arguments].join(" ")}`)"
  lines << "| #{result[:script]}#{result[:arguments].empty? ? "" : " `#{result[:arguments].join(" ")}`"}#{server_mode} | #{result[:counts]["PASS"]} | " \
           "#{result[:explained].size} | #{result[:is_complete] ? result[:unexplained].size : "no summary"} | #{result[:elapsed].round} |"
end
lines << ""
lines << "## Expected failures and their reasons"
lines << ""
results.each do |result|
  result[:explained].group_by { |(_, pattern)| pattern }.each do |pattern, list|
    lines << "- #{result[:script]}, #{list.size} probes matching `#{pattern}`: #{result[:expected][pattern]}"
  end
  lines << "- #{result[:script]} arguments `#{result[:arguments].join(" ")}`: #{result[:arguments_reason]}" if result[:arguments_reason]
end
lines << ""
lines << "## Not run"
lines << ""
CONFIG["not_run"].each { |script, reason| lines << "- #{script}: #{reason}" }
unless total_unexplained.zero?
  lines << ""
  lines << "## Unexplained failures"
  lines << ""
  results.each { |result| result[:unexplained].each { |name| lines << "- #{result[:script]}: #{name}" } }
end
report = lines.join("\n") + "\n"
File.write(options[:report], report) if options[:report]
puts report
exit(total_unexplained.zero? && incomplete.empty? ? 0 : 1)
