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
# Assembly written inside a function (the compression functions that use the
# processor's SHA instructions) is opaque to that analysis, so it is checked
# by its text instead:
#   - every instruction must be on a list of instructions whose timing does
#     not depend on the values they work on (moves, adds, exclusive ors,
#     shuffles, loads and stores, multiplications, conditional selects, and
#     the SHA and AES instructions themselves);
#   - the only conditional branch allowed closes the loop, directly after the
#     instruction that counts the blocks left down by one, and nothing else
#     may write the counting register after it is set from the block count
#     (an operand, or a constant such as RSA's word count);
#   - memory is addressed only as a register plus a constant, so no address
#     is computed from data.
# Everything its pointer arguments lead to is then treated as secret. An
# empty assembly statement is a value barrier: it passes its argument through.
#
# Lengths, offsets and counters stay public, as the constant-time rules
# allow. The check passes when every finding is in the probe's
# deliberate leaks (`leaky_comparison` and the others), which are there to
# prove the checker reports a leak.
#
# Limits, stated plainly: this is a taint analysis written for this code, one
# function at a time. Secrets that enter a function only as plain integer
# arguments are followed from the caller's side as "passed on" notes, and a
# pointer the optimizer rebuilds from integers keeps its origin but loses its
# field. The memory-checker run (spec/probes/secret_taint.cr under Valgrind)
# and the timing check cover the same code by two other methods.

ANALYZED_FUNCTION = /Beryl::Crypto|SecretFlowProbe|Crypto::Subtle/.freeze

# Functions whose every pointer argument leads to secret memory: the cipher
# and authenticator cores, which work on keys, round keys, accumulators and
# message blocks handed to them as bare pointers.
SECRET_BUFFER_FUNCTION = /BitslicedAdvancedEncryptionStandard::|ChaCha20StreamCipher::|Poly1305OneTimeAuthenticator::|
                          GaloisHash::|CipherBlockChaining::|ChaCha20Poly1305Construction::|
                          GaloisCounterModeWithProcessorInstructions::|ChaCha20WithVectorInstructions::|
                          Poly1305WithWideMultiplication::|CipherBlockChainingWithProcessorInstructions::|
                          MontgomeryArithmetic::/x.freeze

# Methods of the cipher objects. A cipher object keeps integers that are
# public (a round count, a tag size) beside buffers that are secret (a key,
# round keys, a hash key), so every buffer loaded from the object is secret
# and its integers are not.
CIPHER_OBJECT_METHOD = /AuthenticatedEncryption|GaloisCounterMode|CipherBlockChainingMode|RivestShamirAdleman::/.freeze

# Functions of the elliptic-curve code that take secrets by value: field
# elements and scalars as arrays of limbs, points as structs of them, a
# clamped scalar as an array of bytes. Every argument of one is secret,
# except one named in PUBLIC_ARGUMENT: an exponent (a public constant of
# the curve that square-and-multiply may branch on), a count of squarings,
# or the position and length of a chunk.
SECRET_VALUE_FUNCTION = /FieldArithmetic::|Curve25519FieldElement[\#:]|DiffieHellmanOverCurve25519::ladder|
                         Edwards25519Group::(?:Point\#(?:add|double|negate|select|encode)|multiply_base|multiply_constant_time|
                         Scalar::(?:reduce|chunk|encode|multiply_add))|
                         ::Arithmetic::(?:Point\#(?:add|double|negate|replace_if)|multiply_constant_time|multiply_generator|
                         multiples_of|to_affine|field_|scalar_power|reduce_once_modulo_order|limbs_|x_coordinate_modulo_order|below_bit)|
                         ConstantTimeSelection::|DeterministicSignatureNonce|SecretFlowProbe::leaky_limb_lookup/x.freeze
PUBLIC_ARGUMENT = /\A%(?:exponent|count|start|bytesize)\z/.freeze

# Functions written for public data: the signature encoder, whose input is
# a signature about to be returned. They may branch on what they are given,
# so a secret must not reach one unless it went through
# Declassification.reveal first; the check reports it when one does.
PUBLIC_DATA_FUNCTION = /EllipticCurveSignatureEncoding::/.freeze

# The one place a verdict computed from secrets may decide what happens
# next (src/beryl/crypto/declassification.cr). Its result is public.
DECLASSIFICATION = /Beryl::Crypto::Declassification::reveal/.freeze
SKIPPED_FUNCTION = /Exception::new|raise</.freeze
EXPECTED_LEAK = /SecretFlowProbe::leaky_/.freeze
LIST_OF_EXPECTED_LEAKS = [/SecretFlowProbe::leaky_comparison</, /SecretFlowProbe::leaky_comparison_of_round_keys</,
                          /SecretFlowProbe::leaky_limb_lookup</, /SecretFlowProbe::leaky_table_selection</].freeze
COMPRESSION_FUNCTION = /#compress(?:_with_portable_code)?</.freeze

# Instructions allowed in assembly: none of them takes a time that depends on
# its operands' values, and none of them indexes memory by a value.
CONSTANT_TIME_ASSEMBLY_INSTRUCTIONS = %w[
  mov movz movk movi dup adr ldr str ld1 st1 add sub eor ext rev32 rev64
  sha1c sha1p sha1m sha1h sha1su0 sha1su1 sha256h sha256h2 sha256su0 sha256su1
  sha512h sha512h2 sha512su0 sha512su1
  lea movdqa movdqu paddd pxor pshufd pshufb palignr pblendw pinsrd pextrd
  sha1rnds4 sha1nexte sha1msg1 sha1msg2 sha256rnds2 sha256msg1 sha256msg2
  aesenc aesenclast aesdec aesdeclast aesimc pclmulqdq bswap pcmpgtd pand por psllq psrlq pslldq psrldq pslld psrld
  aese aesmc aesd pmull pmull2 eor3 rev tbl trn1 trn2 ushr shl sshr sli and orr ldp stp ld1r ld4r
  adds adcs adc mul umulh ror
  lsl lsr subs sbcs sbc csel cmp
  movq mulq addq adcq subq sbbq shlq shrq cmovncq movl movabsq
].freeze
LOOP_COUNT_DOWN = /\A(?:subs (\w+), \1, #1|dec %(\w+))\z/.freeze
LOOP_BRANCH = /\A(?:b\.ne|jnz) 1b\z/.freeze
FORWARD_JUMP = /\A(?:b|jmp) 9f\z/.freeze
STRAIGHT_LINE_BREAKER = /\b(?:b\.\w+|jnz|jmp|b)\s+\d[bf]\b|^\s*\d+:/.freeze
REGISTER_INDEXED_MEMORY = /\[\s*\w+\s*,\s*[a-z]|\(\s*%\w+\s*,/.freeze

# Returns what is wrong with the text of one assembly statement, as a list of
# sentences; an empty list means it keeps to the rules in the header.
def assembly_faults(template)
  list_of_lines = template.split("\n").map(&:strip).reject { |line| line.empty? || line.match?(/\A(?:\d+:|\.)/) }
  list_of_faults = []
  counting_register = nil
  list_of_lines.each_with_index do |line, index|
    mnemonic = line[/\A[\w.]+/]
    if line.match?(LOOP_BRANCH)
      count_down = list_of_lines[index - 1].to_s.match(LOOP_COUNT_DOWN)
      if count_down
        counting_register = count_down[1] || count_down[2]
      else
        list_of_faults << "a conditional branch does not follow the block count: #{line}"
      end
    elsif line.match?(FORWARD_JUMP) || line.match?(LOOP_COUNT_DOWN)
      next
    elsif !CONSTANT_TIME_ASSEMBLY_INSTRUCTIONS.include?(mnemonic)
      list_of_faults << "instruction outside the constant-time list: #{line}"
    end
    list_of_faults << "memory indexed by a register: #{line}" if line.match?(REGISTER_INDEXED_MEMORY)
  end
  if counting_register
    list_of_writes = list_of_lines.select do |line|
      !line.match?(LOOP_COUNT_DOWN) && line.match?(/\A\w+ #{counting_register}\b|, %#{counting_register}\z/)
    end
    unless list_of_writes.size == 1 && list_of_writes[0].match?(/\Amov (?:#{counting_register}, (?:\$\d+|#\d+)|\$\d+, %#{counting_register})\z/)
      list_of_faults << "the block-counting register #{counting_register} is written by: #{list_of_writes.join(' | ')}"
    end
  end
  list_of_faults
end
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

# Returns {name => :slice | :pointer | :other} for a `define` line's arguments
# (`SecretFlow` turns a public Slice argument into :public).
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

    kind = if parameter.match?(/%"Slice\(UInt(?:8|32|64)\)"/) then :slice
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
  attr_reader :list_of_findings, :list_of_notes, :list_of_declassifications, :written_state_paths,
              :assembly_statement_count

  def initialize(function, state_paths_by_compression_function)
    @function = function
    @state_paths_by_compression_function = state_paths_by_compression_function
    @is_compression = function.name.match?(COMPRESSION_FUNCTION)
    @is_secret_buffer_function = function.name.match?(SECRET_BUFFER_FUNCTION)
    @is_cipher_object_method = function.name.match?(CIPHER_OBJECT_METHOD)
    @is_secret_value_function = function.name.match?(SECRET_VALUE_FUNCTION)
    # A public argument passed as a Slice (an exponent) is not secret memory.
    if @is_secret_value_function
      function.parameters.each_key do |name|
        function.parameters[name] = :public if function.parameters[name] == :slice && name.match?(PUBLIC_ARGUMENT)
      end
    end
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
    @list_of_declassifications = []
    @freshly_stored_public = {}
    @written_state_paths = {}
    @assembly_statement_count = 0
    function.parameters.each do |name, kind|
      @origin[name] = [name, ""] if kind == :pointer
      @secret_bases[name] = true if @is_compression && name == "%self"
      @secret_bases[name] = true if @is_secret_buffer_function && kind == :pointer
      next unless @is_secret_value_function && !name.match?(PUBLIC_ARGUMENT)

      @secret_bases[name] = true if kind == :pointer
      @secret_values[name] = true if kind == :other
    end
  end

  def run
    loop do
      before = [@secret_values.size, @secret_bases.size, @secret_fields.size, @origin.size]
      @list_of_findings = []
      @list_of_notes = []
      @list_of_declassifications = []
      @freshly_stored_public = {}
      @assembly_statement_count = 0
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

  def secret_base?(pointer)
    origin = @origin[pointer]
    !origin.nil? && @secret_bases.key?(origin[0])
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
        # A slice built here, or returned by a call, still points where it did; an
        # optional slice (a union) still points where the slice inside it did.
        @origin[instruction.result] = @origin[source] if source && @origin.key?(source)
      end
    when "getelementptr"
      visit_getelementptr(instruction, operands)
    when "load"
      pointer = operands.last
      report("memory address depends on a secret", instruction) if pointer && secret?(pointer)
      if pointer && @freshly_stored_public[pointer]
        # Reads back a public value this function stored a moment ago, with
        # no call and no jump in between (a stack slot the optimizer shares).
      elsif pointer && leads_to_secret?(pointer)
        @secret_values[instruction.result] = true
      elsif instruction.text.start_with?("load ptr")
        @origin[instruction.result] = [instruction.result, ""]
        # A buffer that a cipher object owns holds key material.
        @secret_bases[instruction.result] = true if @is_cipher_object_method && pointer && @origin[pointer]&.first == "%self"
      end
    when "store"
      value_text, pointer = instruction.text.sub(/\Astore (?:volatile )?/, "").split(", ptr ", 2)
      pointer = pointer.to_s[VALUE_TOKEN]
      value = value_text.to_s.scan(VALUE_TOKEN).find { |token| @defined[token] }
      report("memory address depends on a secret", instruction) if pointer && secret?(pointer)
      mark_memory_secret(pointer) if value && secret?(value) && pointer
      @freshly_stored_public[pointer] = !(value && secret?(value)) if pointer
    when "br"
      @freshly_stored_public.clear
      report("branch depends on a secret", instruction) if instruction.text.start_with?("br i1") && operands.first && secret?(operands.first)
    when "switch"
      @freshly_stored_public.clear
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

  # `call ... asm "template", "constraints"(arguments)`.
  def visit_assembly(instruction)
    template = instruction.text[/ asm (?:sideeffect |alignstack |inteldialect |unwind )*"((?:[^"\\]|\\.)*)"/, 1].to_s
    template = template.gsub(/\\([0-9A-Fa-f]{2})/) { Regexp.last_match(1).hex.chr }
    list_of_arguments = instruction.text[/"\((.*)\)\z/, 1].to_s.scan(VALUE_TOKEN).select { |token| @defined[token] }
    if template.strip.empty?
      @secret_values[instruction.result] = true if instruction.result && list_of_arguments.any? { |argument| secret?(argument) }
      return
    end

    @freshly_stored_public.clear
    assembly_faults(template).each { |fault| @list_of_findings << Finding.new(@function.name, "assembly", fault[0, 160]) }
    # A statement with no branch at all (the field arithmetic) may take
    # secrets in registers: its text passed the instruction list above, so
    # nothing in it takes a time that depends on them, and its results are
    # secret. A statement with a loop may not, since its count must be public.
    takes_values = !template.match?(STRAIGHT_LINE_BREAKER)
    list_of_arguments.each do |argument|
      mark_memory_secret(argument)
      next unless secret?(argument)

      if takes_values
        @secret_values[instruction.result] = true if instruction.result
      else
        @list_of_findings << Finding.new(@function.name, "assembly is given a secret value", argument)
      end
    end
    @assembly_statement_count += 1
  end

  def visit_call(instruction, operands)
    return visit_assembly(instruction) if instruction.text.match?(/\A(?:call|invoke) [^@]* asm /)

    callee = instruction.text[/@"((?:[^"\\]|\\.)*)"/, 1] || instruction.text[/@([\w.$]+)/, 1].to_s
    if callee.start_with?("llvm.memcpy", "llvm.memmove")
      destination, source = operands
      mark_memory_secret(destination) if source && leads_to_secret?(source)
      return
    end
    @freshly_stored_public.clear unless callee.start_with?("llvm.lifetime", "llvm.dbg")
    if callee.start_with?("llvm.")
      @secret_values[instruction.result] = true if instruction.result && operands.any? { |operand| secret?(operand) }
      return
    end
    if callee.match?(PUBLIC_DATA_FUNCTION)
      if operands.any? { |operand| secret?(operand) || leads_to_secret?(operand) || @function.parameters[operand] == :slice && @is_secret_value_function }
        report("a secret reaches a function written for public data", instruction)
      end
      return
    end
    if callee.match?(DECLASSIFICATION)
      @list_of_declassifications << "#{@function.name}: #{callee}" if operands.any? { |operand| secret?(operand) }
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
      if receiver
        state_paths.each_key do |path|
          @secret_fields["#{receiver[0]}|#{receiver[1]}#{path}"] = true
          @written_state_paths["#{receiver[1]}#{path}"] = true if receiver[0] == "%self"
        end
      end
    end
    # A returned slice or pointer is taken to point into the last buffer the
    # call was given (`final(dst)` returns `dst`), or else into fresh memory.
    if instruction.result
      returned_buffer = operands.drop(1).reverse.find { |operand| @origin.key?(operand) }
      @origin[instruction.result] ||= returned_buffer ? @origin[returned_buffer] : [instruction.result, ""]
    end
    # A number or a verdict that Beryl code computes from secret buffers is
    # secret: a tag comparison, a padding size.
    if instruction.result && callee.match?(ANALYZED_FUNCTION) && instruction.text.match?(/\A(?:call|invoke) (?:[a-z_]+ )*(?:range\([^)]*\) )?i(?:1|8|16|32|64) @/)
      reads_secret_memory = operands.any? { |operand| @function.parameters[operand] == :slice || secret_base?(operand) }
      @secret_values[instruction.result] = true if reads_secret_memory
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
  function.name.match?(ANALYZED_FUNCTION) && !function.name.match?(SKIPPED_FUNCTION) && !function.name.match?(PUBLIC_DATA_FUNCTION)
end
abort "no Beryl::Crypto function found in #{path}" if list_of_functions.empty?

# Compression functions first: the fields they write are the hash state.
# A compression function may hand its blocks to another one (the choice
# between processor instructions and portable code), so the fields are
# collected until a pass adds none.
state_paths_by_compression_function = {}
list_of_compression_functions = list_of_functions.select { |function| function.name.match?(COMPRESSION_FUNCTION) }
loop do
  path_count_before = state_paths_by_compression_function.values.sum(&:size)
  list_of_compression_functions.each do |function|
    state_paths_by_compression_function[function.name] = SecretFlow.new(function, state_paths_by_compression_function).run.written_state_paths
  end
  break if state_paths_by_compression_function.values.sum(&:size) == path_count_before
end

list_of_findings = []
list_of_notes = []
list_of_declassifications = []
assembly_statement_count = 0
list_of_functions.each do |function|
  flow = SecretFlow.new(function, state_paths_by_compression_function).run
  assembly_statement_count += flow.assembly_statement_count
  list_of_findings.concat(flow.list_of_findings)
  list_of_notes.concat(flow.list_of_notes)
  list_of_declassifications.concat(flow.list_of_declassifications)
end

expected, unexpected = list_of_findings.partition { |finding| finding.function_name.match?(EXPECTED_LEAK) }
puts "functions checked: #{list_of_functions.size} (#{state_paths_by_compression_function.size} compression functions)"
list_of_functions.each { |function| puts "  #{function.name[0, 150]}" }
puts "assembly statements checked by their text: #{assembly_statement_count}"
puts "secret values passed on to another function (checked there): #{list_of_notes.uniq.size}"
list_of_notes.uniq.each { |note| puts "  #{note[0, 260]}" }
puts "verdicts revealed through Declassification.reveal: #{list_of_declassifications.uniq.size}"
list_of_declassifications.uniq.each { |declassification| puts "  #{declassification[0, 260]}" }
puts "findings in the deliberate leaks: #{expected.size}"
expected.each { |finding| puts "  #{finding.function_name[/SecretFlowProbe::\w+/]}: #{finding.kind}: #{finding.text}" }
puts "findings anywhere else: #{unexpected.size}"
unexpected.each { |finding| puts "  #{finding.function_name[0, 120]}\n    #{finding.kind}: #{finding.text}" }

list_of_missed_leaks = LIST_OF_EXPECTED_LEAKS.reject { |leak| expected.any? { |finding| finding.function_name.match?(leak) } }
unless list_of_missed_leaks.empty?
  warn "FAIL: a deliberate leak was not reported (#{list_of_missed_leaks.map(&:source).join(", ")}), so the checker cannot be trusted"
  exit 1
end
unless unexpected.empty?
  warn "FAIL: a secret reaches a branch, an index or a division"
  exit 1
end
puts "PASS: no branch, index or division depends on a secret"
