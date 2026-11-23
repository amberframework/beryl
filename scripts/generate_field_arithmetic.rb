#!/usr/bin/ruby
# frozen_string_literal: true

# Writes Beryl's field arithmetic from fiat-crypto's output.
#
#   /usr/bin/ruby scripts/generate_field_arithmetic.rb           write the files
#   /usr/bin/ruby scripts/generate_field_arithmetic.rb --check   exit 1 if any differs
#
# fiat-crypto (https://github.com/mit-plv/fiat-crypto) synthesizes field
# arithmetic together with a machine-checked proof that it computes the
# field operation and runs in constant time. Its `fiat-json` output is the
# same straight-line code as its C output, as data. This script translates
# that data into Crystal one statement at a time:
#
#   - u1, u8 and u64 values become UInt64, u128 values UInt128; every `+`,
#     `-` and `*` uses the wrapping operator of the result's type, and every
#     cast to u1 or u8 masks to that width, exactly as C truncates.
#   - The four primitives every function calls (add with carry, subtract
#     with borrow, the 64 x 64 -> 128 multiply and the conditional move) are
#     written by hand below, and the conditional move keeps fiat-crypto's
#     value barrier (an empty assembly statement) as its C does.
#   - The inversion helpers (`divstep`, `msat`) are left out: Beryl inverts
#     by Fermat's little theorem with the multiplication below.
#
# The input files are vendored under vendor/fiat-crypto/ and checked against
# the sha256 values below before anything is read. Besides the Crystal, the
# script writes the C shim and the case table that
# spec/field_arithmetic/fiat_crypto_equality.cr uses to compare each
# translated function with fiat-crypto's own C on random inputs.

require "digest"
require "json"
require "tmpdir"

REPOSITORY_ROOT = File.expand_path("..", __dir__)
VENDOR_DIRECTORY = File.join(REPOSITORY_ROOT, "vendor", "fiat-crypto")
OUTPUT_DIRECTORY = File.join(REPOSITORY_ROOT, "src", "beryl", "crypto", "field_arithmetic")
EQUALITY_DIRECTORY = File.join(REPOSITORY_ROOT, "spec", "field_arithmetic")
FIAT_CRYPTO_COMMIT = "3d2880ef2803faa9385589a81a835d5828eb3d38"

PINNED_SHA256 = {
  "curve25519_64.json" => "30cd244c417295d599bc06cd636f44df2d06d2c3c7d7aa548c6dc6fd61fe4f23",
  "curve25519_64.c" => "645233c37707ba0580338aa84d8380357078a2c9bb2db80f0c5ff4e979650e3e",
  "curve25519_scalar_64.json" => "67b53ec6bbea6ee576c77a7788705e86367cf341fd0a3bf802d1840c9f7a1526",
  "curve25519_scalar_64.c" => "6ce7b54074efe552d455c087b982bba0f93d41d3d5d9f90fb2d9afaf8a36626a",
  "p256_64.json" => "189970db01e8e2041d07ddda0e578d5cb7039a860e5637af50e43a5acd6f16ea",
  "p256_64.c" => "68cc5c4fa08de660a869a412618a30848f11d18051245013fe53fa4e313ec701",
  "p256_scalar_64.json" => "4214e1223dbd1878276efef33ba56d6b457525c1b2af0da8963728cfdf1e6fb9",
  "p256_scalar_64.c" => "eed8ad2adb15aa8e120ff8f7ded6c6297284724a612f6b284c5afba9bebfae83",
  "p384_64.json" => "1a1d5a315e8a4d4ac4e0f4b2383fc88c7b908204b9a88e42c193edc35f584816",
  "p384_64.c" => "d3cf74220c7b4c2e33e8e225ac91abcf54616140379b3f528ae5f380c4aa5698",
  "p384_scalar_64.json" => "dbc2737b12efa903513efd8ad1ba93c81b6848c816bd9e15d560f535fd7560a8",
  "p384_scalar_64.c" => "d6ce4e2e18de71062e5679e54ae182c0b2e04b90fb3177ecc16035daa312a3e7",
}.freeze

# One field: its fiat-crypto file, the Crystal module and file it becomes,
# what it is for, and the prefix fiat-crypto puts on its function names.
Field = Struct.new(:fiat_name, :module_name, :file_name, :description, :prefix, keyword_init: true)

LIST_OF_FIELDS = [
  Field.new(fiat_name: "curve25519_64", module_name: "Curve25519Field", file_name: "curve25519_field",
            description: "integers modulo 2^255 - 19 in five unsaturated 51-bit limbs (X25519, Ed25519)",
            prefix: "fiat_25519_"),
  Field.new(fiat_name: "curve25519_scalar_64", module_name: "Curve25519ScalarField", file_name: "curve25519_scalar_field",
            description: "integers modulo the Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493, " \
                         "in the Montgomery domain on four 64-bit words",
            prefix: "fiat_25519_scalar_"),
  Field.new(fiat_name: "p256_64", module_name: "P256Field", file_name: "p256_field",
            description: "integers modulo the P-256 prime 2^256 - 2^224 + 2^192 + 2^96 - 1, in the Montgomery domain on four 64-bit words",
            prefix: "fiat_p256_"),
  Field.new(fiat_name: "p256_scalar_64", module_name: "P256ScalarField", file_name: "p256_scalar_field",
            description: "integers modulo the P-256 group order n, in the Montgomery domain on four 64-bit words",
            prefix: "fiat_p256_scalar_"),
  Field.new(fiat_name: "p384_64", module_name: "P384Field", file_name: "p384_field",
            description: "integers modulo the P-384 prime 2^384 - 2^128 - 2^96 + 2^32 - 1, in the Montgomery domain on six 64-bit words",
            prefix: "fiat_p384_"),
  Field.new(fiat_name: "p384_scalar_64", module_name: "P384ScalarField", file_name: "p384_scalar_field",
            description: "integers modulo the P-384 group order n, in the Montgomery domain on six 64-bit words",
            prefix: "fiat_p384_scalar_"),
].freeze

SKIPPED_OPERATION = /(?:divstep(?:_precomp)?|msat|_addcarryx_u\d+|_subborrowx_u\d+|_mulx_u\d+|_cmovznz_u\d+)\z/.freeze
SIGNED_TYPES = %w[i1 i64 i128].freeze
WIDTH_OF_TYPE = {"u1" => 1, "u8" => 8, "u64" => 64, "u128" => 128, "literal" => 128}.freeze

class TranslationError < StandardError; end

def read_pinned(file_name)
  path = File.join(VENDOR_DIRECTORY, file_name)
  bytes = File.binread(path)
  observed = Digest::SHA256.hexdigest(bytes)
  pinned = PINNED_SHA256.fetch(file_name)
  raise TranslationError, "vendor/fiat-crypto/#{file_name}: sha256 is #{observed}, the generator pins #{pinned}" unless observed == pinned

  bytes
end

# The Crystal type a fiat-crypto data type is computed in.
def crystal_kind(datatype)
  case datatype
  when "u128" then :u128
  when "u1", "u8", "u64" then :u64
  else raise TranslationError, "data type #{datatype.inspect} outside the translated set"
  end
end

def literal(text, kind)
  raise TranslationError, "not a literal: #{text}" unless text.match?(/\A0x\h+\z/)

  "#{text}_#{kind == :u128 ? "u128" : "u64"}"
end

def convert(expression, from_kind, to_kind)
  return expression if from_kind == to_kind
  return "#{parenthesized(expression)}.to_u128" if to_kind == :u128

  "#{parenthesized(expression)}.to_u64!"
end

def parenthesized(expression)
  expression.match?(/\A[\w.()\[\]]+\z/) && !expression.include?(" ") ? expression : "(#{expression})"
end

def mask_to(expression, datatype)
  case datatype
  when "u1" then "(#{expression} & 1_u64)"
  when "u8" then "(#{expression} & 0xff_u64)"
  else expression
  end
end

# Translates the body of one fiat-crypto function.
class FunctionTranslation
  attr_reader :crystal_name, :list_of_arguments, :list_of_returns

  def initialize(function, field)
    @function = function
    @field = field
    @crystal_name = function.fetch("operation").delete_prefix(field.prefix)
    @list_of_arguments = function.fetch("arguments")
    @list_of_returns = function.fetch("returns")
    raise TranslationError, "#{function["operation"]}: more than one return" unless @list_of_returns.size == 1

    @kind_by_variable = {}
    @datatype_by_variable = {}
    @list_of_arguments.each { |argument| @kind_by_variable[argument.fetch("name")] = :argument }
  end

  def array_length(datatype)
    datatype[/\[(\d+)\]\z/, 1]&.to_i
  end

  def element_type(datatype)
    datatype.sub(/\[\d+\]\z/, "")
  end

  def crystal_type(datatype)
    length = array_length(datatype)
    return element_type(datatype) == "u8" ? "StaticArray(UInt8, #{length})" : "StaticArray(UInt64, #{length})" if length

    "UInt64"
  end

  def signature
    parameters = @list_of_arguments.map { |argument| "#{argument.fetch("name")} : #{crystal_type(argument.fetch("datatype"))}" }
    "def self.#{@crystal_name}(#{parameters.join(", ")}) : #{crystal_type(@list_of_returns.first.fetch("datatype"))}"
  end

  # Returns [expression, kind] for an operand: a literal, a variable, an
  # argument, an element of an argument array, or a nested operation.
  def operand(node, wanted_kind = nil)
    return expression_of(node) if node.is_a?(Hash)

    text = node.to_s
    if text.match?(/\A0x\h+\z/)
      kind = wanted_kind || :u64
      return [literal(text, kind), kind, "literal"]
    end
    if (element = text.match(/\A(arg\d+)\[(\d+)\]\z/))
      argument = @list_of_arguments.find { |candidate| candidate.fetch("name") == element[1] }
      raise TranslationError, "unknown argument #{text}" unless argument

      access = "#{element[1]}.unsafe_fetch(#{element[2]})"
      return [element_type(argument.fetch("datatype")) == "u8" ? "#{access}.to_u64" : access, :u64, element_type(argument.fetch("datatype"))]
    end
    if (argument = @list_of_arguments.find { |candidate| candidate.fetch("name") == text })
      return [text, :u64, argument.fetch("datatype")]
    end
    kind = @kind_by_variable[text]
    raise TranslationError, "#{@function["operation"]}: unknown variable #{text}" unless kind

    [text, kind, @datatype_by_variable.fetch(text)]
  end

  def expression_of(node)
    datatype = node.fetch("datatype")
    raise TranslationError, "#{@function["operation"]}: signed type #{datatype}" if SIGNED_TYPES.include?(datatype)

    operation = node.fetch("operation")
    list_of_operands = node.fetch("arguments")
    case operation
    when "static_cast"
      inner, inner_kind, inner_datatype = operand(list_of_operands.first, crystal_kind(datatype))
      converted = convert(inner, inner_kind, crystal_kind(datatype))
      already_narrow = WIDTH_OF_TYPE.fetch(inner_datatype, 128) <= WIDTH_OF_TYPE.fetch(datatype, 128)
      [already_narrow ? converted : mask_to(converted, datatype), crystal_kind(datatype), datatype]
    when "+", "-", "*"
      kind = crystal_kind(datatype)
      list_of_parts = list_of_operands.map do |each_operand|
        expression, operand_kind = operand(each_operand, kind)
        parenthesized(convert(expression, operand_kind, kind))
      end
      [mask_to("(#{list_of_parts.join(" &#{operation} ")})", datatype), kind, datatype]
    when "&", "|"
      kind = crystal_kind(datatype)
      list_of_parts = list_of_operands.map do |each_operand|
        expression, operand_kind = operand(each_operand, kind)
        parenthesized(convert(expression, operand_kind, kind))
      end
      [mask_to("(#{list_of_parts.join(" #{operation} ")})", datatype), kind, datatype]
    when "~"
      kind = crystal_kind(datatype)
      expression, operand_kind = operand(list_of_operands.first, kind)
      [mask_to("(~#{parenthesized(convert(expression, operand_kind, kind))})", datatype), kind, datatype]
    when "!"
      unless list_of_operands.first.is_a?(Hash) && list_of_operands.first.fetch("datatype") == "u1"
        raise TranslationError, "#{@function["operation"]}: logical not of a value wider than one bit"
      end
      expression, = operand(list_of_operands.first)
      ["(#{expression} ^ 1_u64)", :u64, "u1"]
    when ">>"
      expression, operand_kind = operand(list_of_operands.first)
      shift = Integer(list_of_operands[1])
      shifted = "(#{parenthesized(expression)} >> #{shift})"
      [mask_to(convert(shifted, operand_kind, crystal_kind(datatype)), datatype), crystal_kind(datatype), datatype]
    when "<<"
      kind = crystal_kind(datatype)
      expression, operand_kind = operand(list_of_operands.first, kind)
      shift = Integer(list_of_operands[1])
      [mask_to("(#{parenthesized(convert(expression, operand_kind, kind))} << #{shift})", datatype), kind, datatype]
    when "addcarryx", "subborrowx", "mulx", "cmovznz"
      [primitive_call(node), :u64, "u64"]
    else
      raise TranslationError, "#{@function["operation"]}: operation #{operation.inspect} outside the translated set"
    end
  end

  def primitive_call(node)
    operation = node.fetch("operation")
    size = node.dig("parameters", "size") || 64
    list_of_parts = node.fetch("arguments").map do |each_operand|
      expression, operand_kind = operand(each_operand, :u64)
      convert(expression, operand_kind, :u64)
    end
    "#{operation}_u#{size}(#{list_of_parts.join(", ")})"
  end

  def list_of_body_lines
    return_entry = @list_of_returns.first
    return_name = return_entry.fetch("name")
    return_type = return_entry.fetch("datatype")
    lines = []
    lines << "#{return_name} = uninitialized #{crystal_type(return_type)}" if array_length(return_type)
    @function.fetch("body").each do |statement|
      list_of_names = statement.fetch("name")
      operation = statement.fetch("operation")
      if %w[addcarryx subborrowx mulx].include?(operation)
        list_of_names.each_with_index do |name, index|
          next if name == "_"

          @kind_by_variable[name] = :u64
          # The second result of an add or subtract is the carry or borrow: 0 or 1.
          @datatype_by_variable[name] = operation != "mulx" && index == 1 ? "u1" : "u64"
        end
        lines << "#{list_of_names.join(", ")} = #{primitive_call(statement)}"
        next
      end
      raise TranslationError, "#{@function["operation"]}: a statement with #{list_of_names.size} names" unless list_of_names.size == 1

      name = list_of_names.first
      expression, kind, value_datatype =
        if operation == "="
          operand(statement.fetch("arguments").first, :u64)
        else
          expression_of(statement)
        end
      if (element = name.match(/\A(out\d+)\[(\d+)\]\z/))
        value = convert(expression, kind, :u64)
        value = "#{parenthesized(value)}.to_u8!" if element_type(return_type) == "u8"
        lines << "#{element[1]}.unsafe_put(#{element[2]}, #{value})"
      elsif name == return_name
        lines << "#{name} = #{convert(expression, kind, :u64)}"
      else
        @kind_by_variable[name] = kind
        @datatype_by_variable[name] = statement.fetch("datatype") == "(auto)" ? value_datatype : statement.fetch("datatype")
        lines << "#{name} = #{expression}"
      end
    end
    lines << return_name
    lines
  end
end

def primitives_source(uses_51_bit_limbs)
  source = <<~CRYSTAL
    # Value barrier: the optimizer cannot see through the empty assembly
    # statement, so it cannot turn a mask built from a secret back into a
    # branch (fiat-crypto's `value_barrier_u64`).
    @[AlwaysInline]
    def self.value_barrier(value : UInt64) : UInt64
      barred = value
      asm("" : "=r"(barred) : "0"(value))
      barred
    end

    # Returns {(arg1 + arg2 + arg3) mod 2^64, the carry out}.
    @[AlwaysInline]
    def self.addcarryx_u64(arg1 : UInt64, arg2 : UInt64, arg3 : UInt64) : {UInt64, UInt64}
      sum = arg1.to_u128 &+ arg2.to_u128 &+ arg3.to_u128
      {sum.to_u64!, (sum >> 64).to_u64!}
    end

    # Returns {(arg2 - arg1 - arg3) mod 2^64, the borrow out}.
    @[AlwaysInline]
    def self.subborrowx_u64(arg1 : UInt64, arg2 : UInt64, arg3 : UInt64) : {UInt64, UInt64}
      difference = arg2.to_u128 &- arg1.to_u128 &- arg3.to_u128
      {difference.to_u64!, (difference >> 127).to_u64!}
    end

    # Returns {the low word, the high word} of arg1 * arg2.
    @[AlwaysInline]
    def self.mulx_u64(arg1 : UInt64, arg2 : UInt64) : {UInt64, UInt64}
      product = arg1.to_u128 &* arg2.to_u128
      {product.to_u64!, (product >> 64).to_u64!}
    end

    # Returns arg3 when arg1 is nonzero, else arg2, without a branch.
    @[AlwaysInline]
    def self.cmovznz_u64(arg1 : UInt64, arg2 : UInt64, arg3 : UInt64) : UInt64
      mask = 0_u64 &- ((arg1 | (0_u64 &- arg1)) >> 63)
      (value_barrier(mask) & arg3) | (value_barrier(~mask) & arg2)
    end
  CRYSTAL
  return source unless uses_51_bit_limbs

  source + <<~CRYSTAL

    # Returns {(arg1 + arg2 + arg3) mod 2^51, the carry out}.
    @[AlwaysInline]
    def self.addcarryx_u51(arg1 : UInt64, arg2 : UInt64, arg3 : UInt64) : {UInt64, UInt64}
      sum = arg1 &+ arg2 &+ arg3
      {sum & 0x7ffffffffffff_u64, sum >> 51}
    end

    # Returns {(arg2 - arg1 - arg3) mod 2^51, the borrow out}.
    @[AlwaysInline]
    def self.subborrowx_u51(arg1 : UInt64, arg2 : UInt64, arg3 : UInt64) : {UInt64, UInt64}
      difference = arg2 &- arg1 &- arg3
      {difference & 0x7ffffffffffff_u64, difference >> 63}
    end
  CRYSTAL
end

def indent(text, spaces)
  text.lines.map { |line| line.strip.empty? ? "\n" : (" " * spaces) + line }.join
end

def crystal_source(field, list_of_translations, json_sha256)
  limb_count = list_of_translations.first.list_of_arguments.first.fetch("datatype")[/\[(\d+)\]/, 1]
  lines = []
  lines << "# GENERATED by scripts/generate_field_arithmetic.rb from"
  lines << "# vendor/fiat-crypto/#{field.fiat_name}.json (fiat-crypto #{FIAT_CRYPTO_COMMIT},"
  lines << "# sha256 #{json_sha256}). Do not edit; change the generator and run it again."
  lines << "module Beryl::Crypto::FieldArithmetic"
  lines << "  # :nodoc:"
  lines << "  #"
  lines << "  # Arithmetic on #{field.description}, translated"
  lines << "  # statement by statement from fiat-crypto's verified, constant-time code."
  lines << "  # Each method states fiat-crypto's input and output bounds."
  lines << "  module #{field.module_name}"
  lines << "    # A field element as fiat-crypto lays it out."
  lines << "    alias Limbs = StaticArray(UInt64, #{limb_count})"
  lines << ""
  lines << indent(primitives_source(field.fiat_name == "curve25519_64"), 4).rstrip
  list_of_translations.each do |translation|
    lines << ""
    bounds = translation.list_of_arguments.map do |argument|
      lower = Array(argument.fetch("lbound")).join(", ")
      upper = Array(argument.fetch("ubound")).join(", ")
      "#{argument.fetch("name")} in [#{lower}] .. [#{upper}]"
    end
    output = translation.list_of_returns.first
    lines << "    # fiat-crypto `#{field.prefix}#{translation.crystal_name}`."
    bounds.each { |bound| lines << "    # Input bounds: #{bound}." }
    lines << "    # Output bounds: [#{Array(output.fetch("lbound")).join(", ")}] .. [#{Array(output.fetch("ubound")).join(", ")}]."
    lines << "    #{translation.signature}"
    translation.list_of_body_lines.each { |line| lines << "      #{line}" }
    lines << "    end"
  end
  lines << "  end"
  lines << "end"
  lines.join("\n") + "\n"
end

def c_type_of(datatype, is_output)
  length = datatype[/\[(\d+)\]\z/, 1]
  element = datatype.sub(/\[\d+\]\z/, "")
  c_element = element == "u8" ? "uint8_t" : (element == "u1" ? "unsigned char" : "uint64_t")
  return "#{is_output ? "" : "const "}#{c_element} *" if length
  return "#{c_element} *" if is_output

  c_element
end

def c_shim_source(list_of_field_translations)
  lines = []
  lines << "/* GENERATED by scripts/generate_field_arithmetic.rb. Do not edit."
  lines << " *"
  lines << " * Exports fiat-crypto's own C functions (the .c files in vendor/fiat-crypto, commit"
  lines << " * #{FIAT_CRYPTO_COMMIT}) under plain names, so the equality spec can compare"
  lines << " * each with its Crystal translation. Built for that spec only. */"
  lines << "#include <stdint.h>"
  list_of_field_translations.each do |field, list_of_translations|
    lines << ""
    lines << "#include \"../../vendor/fiat-crypto/#{field.fiat_name}.c\""
    list_of_translations.each do |translation|
      output = translation.list_of_returns.first
      list_of_parameters = ["#{c_type_of(output.fetch("datatype"), true)}out1"]
      translation.list_of_arguments.each do |argument|
        list_of_parameters << "#{c_type_of(argument.fetch("datatype"), false)} #{argument.fetch("name")}".sub("* ", "*")
      end
      list_of_call_arguments = ["out1"] + translation.list_of_arguments.map { |argument| argument.fetch("name") }
      lines << "void beryl_#{field.prefix}#{translation.crystal_name}(#{list_of_parameters.join(", ")}) {"
      lines << "  #{field.prefix}#{translation.crystal_name}(#{list_of_call_arguments.join(", ")});"
      lines << "}"
    end
  end
  lines.join("\n") + "\n"
end

def crystal_type_for_case(datatype)
  length = datatype[/\[(\d+)\]\z/, 1]
  element = datatype.sub(/\[\d+\]\z/, "")
  return "UInt8" if length && element == "u8"
  return "UInt64" if length

  element == "u1" ? "UInt8" : "UInt64"
end

# The cases of the equality spec: each function, its C twin, and the bounds
# its inputs are drawn from.
def equality_cases_source(list_of_field_translations)
  lines = []
  lines << "# GENERATED by scripts/generate_field_arithmetic.rb. Do not edit."
  lines << "#"
  lines << "# fiat-crypto's C functions (spec/field_arithmetic/fiat_crypto_c_shim.c) and,"
  lines << "# for each, a check that its Crystal translation returns the same bytes on"
  lines << "# inputs drawn inside fiat-crypto's input bounds."
  lines << "{% begin %}"
  lines << "@[Link(ldflags: \"{{ __DIR__.id }}/fiat_crypto_c_shim.o\")]"
  lines << "lib LibFiatCryptoC"
  list_of_field_translations.each do |field, list_of_translations|
    list_of_translations.each do |translation|
      output = translation.list_of_returns.first
      list_of_parameters = ["out1 : #{crystal_type_for_case(output.fetch("datatype"))}*"]
      translation.list_of_arguments.each do |argument|
        datatype = argument.fetch("datatype")
        pointer = datatype.include?("[") ? "*" : ""
        list_of_parameters << "#{argument.fetch("name")} : #{crystal_type_for_case(datatype)}#{pointer}"
      end
      lines << "  fun #{field.fiat_name}_#{translation.crystal_name} = beryl_#{field.prefix}#{translation.crystal_name}(#{list_of_parameters.join(", ")}) : Void"
    end
  end
  lines << "end"
  lines << "{% end %}"
  lines << ""
  lines << "module FiatCryptoEquality"
  lines << "  # {field, function, check}: each check draws *count* inputs from the"
  lines << "  # generator and returns the number of inputs on which the two differ."
  lines << "  LIST_OF_CASES = ["
  list_of_field_translations.each do |field, list_of_translations|
    list_of_translations.each do |translation|
      lines.concat(equality_case_lines(field, translation).map { |line| "    #{line}" })
    end
  end
  lines << "  ] of {String, String, Proc(Int64, InputDraw, Int64)}"
  lines << "end"
  lines.join("\n") + "\n"
end

def equality_case_lines(field, translation)
  output = translation.list_of_returns.first
  output_type = output.fetch("datatype")
  output_length = output_type[/\[(\d+)\]\z/, 1]
  lines = []
  lines << "{#{field.module_name.inspect}, #{translation.crystal_name.inspect}, ->(count : Int64, draw : InputDraw) do"
  lines << "  differences = 0_i64"
  translation.list_of_arguments.each do |argument|
    datatype = argument.fetch("datatype")
    lower = Array(argument.fetch("lbound")).map { |bound| "#{bound}_u64" }
    upper = Array(argument.fetch("ubound")).map { |bound| "#{bound}_u64" }
    lines << "  lower_#{argument.fetch("name")} = [#{lower.join(", ")}]"
    lines << "  upper_#{argument.fetch("name")} = [#{upper.join(", ")}]"
    if datatype.include?("[")
      length = datatype[/\[(\d+)\]\z/, 1]
      element = crystal_type_for_case(datatype)
      lines << "  #{argument.fetch("name")} = StaticArray(#{element}, #{length}).new(0)"
    end
  end
  lines << "  count.times do"
  call_arguments = []
  c_arguments = []
  translation.list_of_arguments.each do |argument|
    name = argument.fetch("name")
    datatype = argument.fetch("datatype")
    if datatype.include?("[")
      element = crystal_type_for_case(datatype)
      lines << "    #{name}.size.times { |index| #{name}[index] = draw.next_within(lower_#{name}[index], upper_#{name}[index]).to_#{element == "UInt8" ? "u8" : "u64"} }"
      call_arguments << name
      c_arguments << "#{name}.to_unsafe"
    else
      element = crystal_type_for_case(datatype)
      lines << "    #{name} = draw.next_within(lower_#{name}[0], upper_#{name}[0])"
      call_arguments << name
      c_arguments << (element == "UInt8" ? "#{name}.to_u8" : name)
    end
  end
  lines << "    translated = Beryl::Crypto::FieldArithmetic::#{field.module_name}.#{translation.crystal_name}(#{call_arguments.join(", ")})"
  if output_length
    lines << "    from_c = StaticArray(#{crystal_type_for_case(output_type)}, #{output_length}).new(0)"
    lines << "    LibFiatCryptoC.#{field.fiat_name}_#{translation.crystal_name}(#{(["from_c.to_unsafe"] + c_arguments).join(", ")})"
  else
    lines << "    from_c = 0_u64"
    lines << "    LibFiatCryptoC.#{field.fiat_name}_#{translation.crystal_name}(#{(["pointerof(from_c)"] + c_arguments).join(", ")})"
  end
  lines << "    differences += 1 unless translated == from_c"
  lines << "  end"
  lines << "  differences"
  lines << "end},"
  lines
end

list_of_field_translations = LIST_OF_FIELDS.map do |field|
  json_bytes = read_pinned("#{field.fiat_name}.json")
  read_pinned("#{field.fiat_name}.c")
  list_of_functions = JSON.parse(json_bytes)
  list_of_translations = list_of_functions.reject { |function| function.fetch("operation").match?(SKIPPED_OPERATION) }
                                          .map { |function| FunctionTranslation.new(function, field) }
  [field, list_of_translations, Digest::SHA256.hexdigest(json_bytes)]
end

list_of_outputs = list_of_field_translations.map do |field, list_of_translations, json_sha256|
  [File.join(OUTPUT_DIRECTORY, "#{field.file_name}.cr"), crystal_source(field, list_of_translations, json_sha256)]
end
pairs = list_of_field_translations.map { |field, list_of_translations, _| [field, list_of_translations] }
list_of_outputs << [File.join(EQUALITY_DIRECTORY, "fiat_crypto_c_shim.c"), c_shim_source(pairs)]
list_of_outputs << [File.join(EQUALITY_DIRECTORY, "fiat_crypto_equality_cases.cr"), equality_cases_source(pairs)]

# The Crystal files go through `crystal tool format`, which owns the layout of
# every Crystal file in this repository (CRYSTAL names the compiler; the
# default is crystal-alpha, then crystal).
def formatted(list_of_outputs)
  compiler = ENV["CRYSTAL"] || (system("command -v crystal-alpha > /dev/null") ? "crystal-alpha" : "crystal")
  Dir.mktmpdir("beryl-field-arithmetic-") do |directory|
    list_of_outputs.map.with_index do |(path, contents), index|
      next [path, contents] unless path.end_with?(".cr")

      draft = File.join(directory, "draft_#{index}.cr")
      File.write(draft, contents)
      raise TranslationError, "#{compiler} tool format failed on #{path}" unless system(compiler, "tool", "format", draft, out: File::NULL)

      [path, File.read(draft)]
    end
  end
end

list_of_outputs = formatted(list_of_outputs)

if ARGV.include?("--check")
  list_of_stale = list_of_outputs.reject { |path, contents| File.exist?(path) && File.read(path) == contents }
  if list_of_stale.empty?
    puts "the generated field arithmetic matches vendor/fiat-crypto (#{list_of_outputs.size} files)"
  else
    warn "out of date with vendor/fiat-crypto (run scripts/generate_field_arithmetic.rb): #{list_of_stale.map(&:first).join(", ")}"
    exit 1
  end
else
  list_of_outputs.each do |path, contents|
    Dir.mkdir(File.dirname(path)) unless Dir.exist?(File.dirname(path))
    File.write(path, contents)
    puts "wrote #{path.delete_prefix(REPOSITORY_ROOT + "/")}"
  end
end
