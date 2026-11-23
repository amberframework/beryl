require "./processor_features"

module Beryl::Crypto
  # :nodoc:
  #
  # Runs work on secrets with the processor's Data Independent Timing mode
  # on (PSTATE.DIT, Armv8.4). Without it, Arm allows a data-processing
  # instruction to take a time that depends on its operands, and on Apple
  # M4 it does: an X25519 multiplication by a scalar with few set bits ran
  # measurably faster than by a random scalar, although the compiled code
  # has no branch and no table index that depends on the scalar
  # (spec/constant_time/public_key_timing_spec.cr). With DIT on, the two
  # cannot be told apart. Apple asks for DIT around cryptographic work.
  #
  # The mode belongs to the thread. `run` turns it on, runs the block and
  # turns it off again unless it was already on, so calls nest. Processors
  # without the mode (x86-64, older Arm) run the block as it is.
  module DataIndependentTiming
    # `msr dit, #1`, `msr dit, #0` and `mrs x0, dit`, written as their
    # encodings so that no assembler target feature is needed.
    def self.run(&)
      {% if flag?(:aarch64) %}
        if ProcessorFeatures::HAS_DATA_INDEPENDENT_TIMING
          was_on = turn_on
          begin
            return yield
          ensure
            turn_off unless was_on
          end
        end
      {% end %}
      yield
    end

    {% if flag?(:aarch64) %}
      # Turns the mode on and returns whether it was on before.
      @[AlwaysInline]
      private def self.turn_on : Bool
        state = 0_u64
        asm(".inst 0xd53b42a0" : "={x0}"(state) :: "memory" : "volatile")
        asm(".inst 0xd503415f" :::: "volatile")
        state.bit(24) == 1
      end

      @[AlwaysInline]
      private def self.turn_off : Nil
        asm(".inst 0xd503405f" :::: "volatile")
      end
    {% end %}
  end
end
