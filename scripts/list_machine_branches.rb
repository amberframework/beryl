#!/usr/bin/ruby
# frozen_string_literal: true

# Lists the conditional branches, divisions and computed jumps in the final
# x86-64 machine code of the curve functions, from `objdump -d` output.
#
#   objdump -d --no-show-raw-insn -C curve_timing_probe > probe.dis
#   /usr/bin/ruby scripts/list_machine_branches.rb probe.dis [pattern]
#
# Investigation aid: prints each function whose name matches the pattern,
# its instruction count, and every jcc, div, idiv or indirect jump with the
# instructions just before it, so a person can tell a loop counter from a
# value-dependent branch.

FUNCTION_HEADER = /^[0-9a-f]+ <(.+)>:$/.freeze
INSTRUCTION = /^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$/.freeze
WATCHED = /\A(j(?!mp)[a-z]+|div[a-z]*|idiv[a-z]*|cmov[a-z]+|set[a-z]+)\z/.freeze
ALARMING = /\A(j(?!mp)[a-z]+|div[a-z]*|idiv[a-z]*)\z/.freeze

path = ARGV.fetch(0)
pattern = Regexp.new(ARGV.fetch(1, "P256|Arithmetic|Curve25519|X25519|Edwards25519|FieldArithmetic|CurveTimingProbe|ConstantTimeSelection"))

functions = {}
current = nil
File.foreach(path) do |line|
  if (header = FUNCTION_HEADER.match(line))
    current = header[1]
    functions[current] = []
  elsif current && (instruction = INSTRUCTION.match(line))
    functions[current] << [instruction[1], instruction[2], instruction[3]]
  end
end

functions.each do |name, instructions|
  next unless pattern.match?(name)

  counts = Hash.new(0)
  instructions.each { |(_, mnemonic, _)| counts[mnemonic.sub(/[bwlq]\z/, "")] += 1 if WATCHED.match?(mnemonic) }
  alarming = instructions.each_index.select { |index| ALARMING.match?(instructions[index][1]) }
  puts "== #{name}: #{instructions.size} instructions; #{counts.sort.map { |mnemonic, count| "#{mnemonic} #{count}" }.join(", ")}"
  alarming.each do |index|
    context = instructions[[index - 3, 0].max..index].map { |(address, mnemonic, operands)| "#{address}: #{mnemonic} #{operands}".strip }
    puts "   #{context.join(" | ")}"
  end
end
