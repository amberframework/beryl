#!/usr/bin/ruby
# frozen_string_literal: true

# Static constant-time check of Beryl's compiled code.
#
#   /usr/bin/ruby scripts/check_secret_flow.rb secret_flow.ll
#
# Reads the optimized LLVM IR of spec/probes/secret_flow.cr and follows secret
# bytes through every function of Beryl::Crypto and of the probe. It reports
# each place where a secret decides a conditional branch or a switch, indexes
# memory, or is divided: the three ways a value changes how long code runs.
#
# What counts as secret:
#   - the bytes behind every Slice(UInt8) argument (keys, messages, tags);
#   - in a compression function, the hash state as well (everything read
#     through `self`);
#   - anything computed from a secret, and any memory a secret was stored in.
#     Memory is tracked per field: a base pointer plus the constant offsets
#     that lead to the field, so a length stored beside a secret buffer stays
#     public;
#   - after a call to a compression function, the state fields that function
#     writes, in the object that was passed to it;
#   - a byte buffer of 16 bytes or more on the stack once it has been handed
#     to another function, which may have written a digest or a tag into it
#     (smaller ones are the block counters of HKDF and PBKDF2, which are
#     public).
#
# Lengths, offsets and counters stay public, as the constant-time rules
# allow. The check passes when every finding is in the probe's
# `leaky_comparison`, which is there to prove the checker reports a leak.
#
# Limits, stated plainly: this is a taint analysis written for this code, one
# function at a time. Secrets that enter a function only as plain integer
# arguments are followed from the caller's side as "passed on" notes, and a
# pointer the optimizer rebuilds from integers keeps its origin but loses its
# field. The memory-checker run (spec/probes/secret_taint.cr under Valgrind)
# and the timing check cover the same code by two other methods.

ANALYZED_FUNCTION = /Beryl::Crypto|SecretFlowProbe|Crypto::Subtle/.freeze
SKIPPED_FUNCTION = /Exception::new|raise</.freeze
EXPECTED_LEAK = /SecretFlowProbe::leaky_comparison/.freeze
COMPRESSION_FUNCTION = /#compress</.freeze
VALUE_TOKEN = /%"[^"]*"|%[\w.\-$]+/.freeze
POINTER_PASSING_OPCODES = %w[bitcast addrspacecast ptrtoint inttoptr phi select add sub freeze insertvalue].freeze
DIVISIONS = %w[udiv sdiv urem srem].freeze

# The smallest stack buffer that holds a secret in this code is an MD5 digest.
# Smaller byte buffers on the stack are block counters, which are public.
SMALLEST_SECRET_BUFFER_BYTESIZE = 16

Function = Struct.new(:name, :parameters, :list_of_instructions)
Instruction = Struct.new(:result, :opcode, :text, :list_of_operands)
Finding = Struct.new(:function_name, :kind, :text)

def read_functions(path)
  list_of_functions = []
  current = nil
  File.foreach(path) do |raw_line|
    line = raw_line.chomp
    if line.start_with?("define ")
      name_match = line.match(/@"([^"]*)"\(/) || line.match(/@([\w.$]+)\(/)
      parameter_text = line[(name_match.end(0) - 1)..]
      current = Function.new(name_match[1], parse_parameters(parameter_text), [])
    elsif line == "}"
      list_of_functions << current if current
      current = nil
    elsif current
      text = line.sub(/;.*\z/, "").gsub(/, !\w+ !\d+/, "").strip
      next if text.empty? || text.end_with?(":")

      result, body = text.match(/\A(#{VALUE_TOKEN}) = (.*)\z/) ? [Regexp.last_match(1), Regexp.last_match(2)] : [nil, text]
      body = body.sub(/\A(?:tail |musttail |notail )/, "")
      current.list_of_instructions << Instruction.new(result, body[/\A[\w.]+/], body, [])
    end
  end
  list_of_functions
end

# Returns {name => :slice | :pointer | :other} for a `define` line's arguments.
def parse_parameters(parameter_text)
  parameters = {}
  depth = 0
  piece = +""
  list_of_pieces = []
  parameter_text[1..].each_char do |character|
    break if character == ")" && depth.zero?

    depth += 1 if "([{<".include?(character)
    depth -= 1 if ")]}>".include?(character)
    if character == "," && depth.zero?
      list_of_pieces << piece
      piece = +""
    else
      piece << character
    end
  end
  list_of_pieces << piece
  list_of_pieces.each do |parameter|
    name = parameter.strip[/(#{VALUE_TOKEN})\z/, 1]
    next unless name

    kind = if parameter.include?('%"Slice(UInt8)"') then :slice
           elsif parameter.strip.start_with?("ptr") then :pointer
           else :other
           end
    parameters[name] = kind
  end
  parameters
end

# One function's analysis: which values are secret, which pointers lead to
# secret memory, and what was found.
class SecretFlow
  attr_reader :list_of_findings, :list_of_notes, :written_state_paths

  def initialize(function, state_paths_by_compression_function)
    @function = function
    @state_paths_by_compression_function = state_paths_by_compression_function
    @is_compression = function.name.match?(COMPRESSION_FUNCTION)
    @defined = function.parameters.keys.to_h { |name| [name, true] }
    function.list_of_instructions.each { |instruction| @defined[instruction.result] = true if instruction.result }
    function.list_of_instructions.each do |instruction|
      instruction.list_of_operands = instruction.text.scan(VALUE_TOKEN).select { |token| @defined[token] }
    end
    @secret_values = {}
    @origin = {}            # pointer-like value => [base, path]
    @secret_bases = {}      # base => true: everything behind it is secret
    @secret_fields = {}     # "base|path" => true
    @list_of_findings = []
    @list_of_notes = []
    @written_state_paths = {}
    function.parameters.each do |name, kind|
      @origin[name] = [name, ""] if kind == :pointer
      @secret_bases[name] = true if @is_compression && name == "%self"
    end
  end

  def run
    loop do
      before = [@secret_values.size, @secret_bases.size, @secret_fields.size, @origin.size]
      @list_of_findings = []
      @list_of_notes = []
      @function.list_of_instructions.each { |instruction| visit(instruction) }
      break if before == [@secret_values.size, @secret_bases.size, @secret_fields.size, @origin.size]
    end
    self
  end

  private

  def secret?(value)
    @secret_values.key?(value)
  end

  def leads_to_secret?(pointer)
    origin = @origin[pointer]
    return false unless origin

    @secret_bases.key?(origin[0]) || @secret_fields.key?("#{origin[0]}|#{origin[1]}")
  end

  def mark_memory_secret(pointer)
    origin = @origin[pointer]
    return unless origin

    @secret_fields["#{origin[0]}|#{origin[1]}"] = true
    @written_state_paths[origin[1]] = true if origin[0] == "%self"
  end

  def report(kind, instruction)
    @list_of_findings << Finding.new(@function.name, kind, instruction.text[0, 160])
  end

  def visit(instruction)
    operands = instruction.list_of_operands
    case instruction.opcode
    when "alloca"
      @origin[instruction.result] = [instruction.result, ""]
    when "extractvalue"
      source = operands.first
      if @function.parameters[source] == :slice && instruction.text.match?(/, 2\z/)
        @origin[instruction.result] = [instruction.result, ""]
        @secret_bases[instruction.result] = true
      else
        @secret_values[instruction.result] = true if source && secret?(source)
        # A slice built here, or returned by a call, still points where it did.
        @origin[instruction.result] = @origin[source] if source && @origin.key?(source) && instruction.text.match?(/, 2\z/)
      end
    when "getelementptr"
      visit_getelementptr(instruction, operands)
    when "load"
      pointer = operands.last
      report("memory address depends on a secret", instruction) if pointer && secret?(pointer)
      if pointer && leads_to_secret?(pointer)
        @secret_values[instruction.result] = true
      elsif instruction.text.start_with?("load ptr")
        @origin[instruction.result] = [instruction.result, ""]
      end
    when "store"
      value_text, pointer = instruction.text.sub(/\Astore (?:volatile )?/, "").split(", ptr ", 2)
      pointer = pointer.to_s[VALUE_TOKEN]
      value = value_text.to_s.scan(VALUE_TOKEN).find { |token| @defined[token] }
      report("memory address depends on a secret", instruction) if pointer && secret?(pointer)
      mark_memory_secret(pointer) if value && secret?(value) && pointer
    when "br"
      report("branch depends on a secret", instruction) if instruction.text.start_with?("br i1") && operands.first && secret?(operands.first)
    when "switch"
      report("switch depends on a secret", instruction) if operands.first && secret?(operands.first)
    when "call", "invoke"
      visit_call(instruction, operands)
    when *DIVISIONS
      report("division depends on a secret", instruction) if operands.any? { |operand| secret?(operand) }
      @secret_values[instruction.result] = true if operands.any? { |operand| secret?(operand) }
    else
      visit_plain(instruction, operands)
    end
  end

  def visit_getelementptr(instruction, operands)
    base_pointer = operands.first
    list_of_indices = operands.drop(1)
    report("memory index depends on a secret", instruction) if list_of_indices.any? { |index| secret?(index) }
    report("memory address depends on a secret", instruction) if base_pointer && secret?(base_pointer)
    origin = @origin[base_pointer]
    return unless origin

    element_type = instruction.text[/\Agetelementptr (?:inbounds |nuw |nusw )*(.+?), ptr /, 1].to_s
    constant_indices = instruction.text.split(", ptr ", 2).last.to_s.split(", ").drop(1).map { |index| index.split.last }
    step = list_of_indices.empty? ? "#{element_type == "i8" ? "" : element_type}@#{constant_indices.join(",")}" : "var"
    @origin[instruction.result] = [origin[0], "#{origin[1]}/#{step}"]
  end

  def visit_call(instruction, operands)
    callee = instruction.text[/@"((?:[^"\\]|\\.)*)"/, 1] || instruction.text[/@([\w.$]+)/, 1].to_s
    if callee.start_with?("llvm.memcpy", "llvm.memmove")
      destination, source = operands
      mark_memory_secret(destination) if source && leads_to_secret?(source)
      return
    end
    if callee.start_with?("llvm.")
      @secret_values[instruction.result] = true if instruction.result && operands.any? { |operand| secret?(operand) }
      return
    end

    # A stack byte buffer handed to another function may come back holding a
    # digest or a tag.
    operands.each do |operand|
      origin = @origin[operand]
      @secret_bases[origin[0]] = true if origin && byte_buffer_on_stack?(origin[0])
    end
    if (state_paths = @state_paths_by_compression_function[callee])
      receiver = @origin[operands.first]
      state_paths.each_key { |path| @secret_fields["#{receiver[0]}|#{receiver[1]}#{path}"] = true } if receiver
    end
    # A returned slice or pointer is taken to point into the last buffer the
    # call was given (`final(dst)` returns `dst`), or else into fresh memory.
    if instruction.result
      returned_buffer = operands.drop(1).reverse.find { |operand| @origin.key?(operand) }
      @origin[instruction.result] ||= returned_buffer ? @origin[returned_buffer] : [instruction.result, ""]
    end
    list_of_secret_arguments = operands.select { |operand| secret?(operand) }
    return if list_of_secret_arguments.empty?

    @list_of_notes << "#{@function.name}: a secret value is passed on to #{callee}"
    @secret_values[instruction.result] = true if instruction.result
  end

  def byte_buffer_on_stack?(base)
    @byte_buffers ||= @function.list_of_instructions
                               .select { |instruction| instruction.opcode == "alloca" && instruction.text[/alloca \[(\d+) x i8\]/, 1].to_i >= SMALLEST_SECRET_BUFFER_BYTESIZE }
                               .to_h { |instruction| [instruction.result, true] }
    @byte_buffers.key?(base)
  end

  def visit_plain(instruction, operands)
    return unless instruction.result

    @secret_values[instruction.result] = true if operands.any? { |operand| secret?(operand) }
    return unless POINTER_PASSING_OPCODES.include?(instruction.opcode)

    source = operands.find { |operand| @origin.key?(operand) }
    return unless source

    origin = @origin[source]
    @origin[instruction.result] ||= %w[add sub].include?(instruction.opcode) ? [origin[0], "#{origin[1]}/var"] : origin
  end
end

path = ARGV.fetch(0) { abort "usage: check_secret_flow.rb <file.ll>" }
list_of_functions = read_functions(path).select do |function|
  function.name.match?(ANALYZED_FUNCTION) && !function.name.match?(SKIPPED_FUNCTION)
end
abort "no Beryl::Crypto function found in #{path}" if list_of_functions.empty?

# Compression functions first: the fields they write are the hash state.
state_paths_by_compression_function = {}
list_of_functions.select { |function| function.name.match?(COMPRESSION_FUNCTION) }.each do |function|
  state_paths_by_compression_function[function.name] = SecretFlow.new(function, {}).run.written_state_paths
end

list_of_findings = []
list_of_notes = []
list_of_functions.each do |function|
  flow = SecretFlow.new(function, state_paths_by_compression_function).run
  list_of_findings.concat(flow.list_of_findings)
  list_of_notes.concat(flow.list_of_notes)
end

expected, unexpected = list_of_findings.partition { |finding| finding.function_name.match?(EXPECTED_LEAK) }
puts "functions checked: #{list_of_functions.size} (#{state_paths_by_compression_function.size} compression functions)"
list_of_functions.each { |function| puts "  #{function.name[0, 150]}" }
puts "secret values passed on to another function (checked there): #{list_of_notes.uniq.size}"
list_of_notes.uniq.each { |note| puts "  #{note[0, 260]}" }
puts "findings in leaky_comparison (the deliberate leak): #{expected.size}"
expected.each { |finding| puts "  #{finding.kind}: #{finding.text}" }
puts "findings anywhere else: #{unexpected.size}"
unexpected.each { |finding| puts "  #{finding.function_name[0, 120]}\n    #{finding.kind}: #{finding.text}" }

if expected.empty?
  warn "FAIL: the deliberate leak was not reported, so the checker cannot be trusted"
  exit 1
end
unless unexpected.empty?
  warn "FAIL: a secret reaches a branch, an index or a division"
  exit 1
end
puts "PASS: no branch, index or division depends on a secret"
