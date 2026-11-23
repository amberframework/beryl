# Compares every translated field function with fiat-crypto's own C.
#
#     cc -O2 -c spec/field_arithmetic/fiat_crypto_c_shim.c -o spec/field_arithmetic/fiat_crypto_c_shim.o
#     crystal-alpha build --release spec/field_arithmetic/fiat_crypto_equality.cr -o fiat_crypto_equality
#     ./fiat_crypto_equality [inputs per function] [seed] [field name]
#
# `scripts/generate_field_arithmetic.rb` translates fiat-crypto's JSON output
# into Crystal; the C file it compiles here is fiat-crypto's C output from
# the same commit. For each function, the program draws inputs inside
# fiat-crypto's stated input bounds (one draw in eight takes a bound itself,
# or one below the upper bound) and counts the inputs on which the Crystal
# result and the C result differ. It exits 1 if any does.
#
# The plan's gate is 100,000,000 inputs per function (the default). CI runs
# a smaller count on every pull request.
require "../../src/beryl/crypto"

# A xoshiro256** generator: fast enough that drawing inputs costs less than
# the functions under test. Seeded from the command line so a failure replays.
class InputDraw
  @state : StaticArray(UInt64, 4)

  def initialize(seed : UInt64)
    @state = StaticArray(UInt64, 4).new(0_u64)
    mixed = seed
    4.times do |index|
      mixed = mixed &+ 0x9e3779b97f4a7c15_u64
      value = mixed
      value = (value ^ (value >> 30)) &* 0xbf58476d1ce4e5b9_u64
      value = (value ^ (value >> 27)) &* 0x94d049bb133111eb_u64
      @state[index] = value ^ (value >> 31)
    end
  end

  def next_u64 : UInt64
    result = (@state[1] &* 5).rotate_left(7) &* 9
    shifted = @state[1] << 17
    @state[2] ^= @state[0]
    @state[3] ^= @state[1]
    @state[1] ^= @state[2]
    @state[0] ^= @state[3]
    @state[2] ^= shifted
    @state[3] = @state[3].rotate_left(45)
    result
  end

  # Returns a value in lower..upper: a bound itself one time in sixteen each,
  # one below the upper bound one time in sixteen, else uniform.
  def next_within(lower : UInt64, upper : UInt64) : UInt64
    random = next_u64
    case random & 0xf
    when 0 then return lower
    when 1 then return upper
    when 2 then return upper > lower ? upper - 1 : upper
    end
    value = next_u64
    span = upper &- lower
    return value if span == UInt64::MAX

    lower &+ value % (span &+ 1)
  end
end

require "./fiat_crypto_equality_cases"

inputs_per_function = (ARGV[0]? || "100000000").to_i64
seed = (ARGV[1]? || Random::Secure.rand(UInt64).to_s).to_u64
selected_field = ARGV[2]?

STDOUT.puts "fiat-crypto equality: #{inputs_per_function} inputs per function, seed #{seed}"
total_differences = 0_i64
functions_checked = 0
FiatCryptoEquality::LIST_OF_CASES.each_with_index do |(field_name, function_name, check), index|
  next if selected_field && selected_field != field_name

  started_at = Time.instant
  differences = check.call(inputs_per_function, InputDraw.new(seed &+ index.to_u64))
  seconds = (Time.instant - started_at).total_seconds
  STDOUT.puts "#{field_name}.#{function_name}: #{inputs_per_function} inputs, #{differences} differences (#{seconds.round(1)} s)"
  STDOUT.flush
  total_differences += differences
  functions_checked += 1
end
STDOUT.puts "functions checked: #{functions_checked}, inputs: #{functions_checked.to_i64 * inputs_per_function}, differences: #{total_differences}"
exit(total_differences.zero? && functions_checked > 0 ? 0 : 1)
