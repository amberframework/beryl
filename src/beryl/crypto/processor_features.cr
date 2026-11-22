module Beryl::Crypto
  # :nodoc:
  #
  # Tells which hash instructions the processor running this program has, so
  # that each hash can choose between its compression function written with
  # those instructions and its portable one.
  #
  # - Apple Silicon: every such processor has the SHA-1, SHA-256 and SHA-512
  #   instructions, so the answer is known when the program is compiled.
  # - Linux on AArch64: the kernel lists them in the auxiliary vector, read
  #   once when the program starts.
  # - Linux on x86-64: CPUID lists the SHA extensions (SHA-1 and SHA-256),
  #   read once when the program starts.
  # - Anywhere else, and in a program compiled with `-Dberyl_portable_hashes`
  #   (which the test suite uses to run every vector through the portable
  #   code on a machine that has the instructions): none.
  module ProcessorFeatures
    {% if flag?(:beryl_portable_hashes) %}
      HAS_SHA1_INSTRUCTIONS   = false
      HAS_SHA256_INSTRUCTIONS = false
      HAS_SHA512_INSTRUCTIONS = false
    {% elsif flag?(:aarch64) && flag?(:darwin) %}
      HAS_SHA1_INSTRUCTIONS   = true
      HAS_SHA256_INSTRUCTIONS = true
      HAS_SHA512_INSTRUCTIONS = true
    {% elsif flag?(:aarch64) && flag?(:linux) %}
      lib LibAuxiliaryVector
        fun getauxval(type : LibC::ULong) : LibC::ULong
      end

      # `AT_HWCAP` and its `HWCAP_SHA1`, `HWCAP_SHA2` and `HWCAP_SHA512` bits
      # (Linux `arch/arm64/include/uapi/asm/hwcap.h`).
      private HARDWARE_CAPABILITIES_ENTRY = 16
      private SHA1_CAPABILITY             = 1_u64 << 5
      private SHA256_CAPABILITY           = 1_u64 << 6
      private SHA512_CAPABILITY           = 1_u64 << 21

      private def self.has_capability?(capability : UInt64) : Bool
        LibAuxiliaryVector.getauxval(HARDWARE_CAPABILITIES_ENTRY).to_u64 & capability != 0
      end

      HAS_SHA1_INSTRUCTIONS   = has_capability?(SHA1_CAPABILITY)
      HAS_SHA256_INSTRUCTIONS = has_capability?(SHA256_CAPABILITY)
      HAS_SHA512_INSTRUCTIONS = has_capability?(SHA512_CAPABILITY)
    {% elsif flag?(:x86_64) && flag?(:linux) %}
      # Returns the EAX, EBX, ECX and EDX registers that CPUID gives for
      # *leaf* and *subleaf*.
      private def self.processor_identification(leaf : UInt32, subleaf : UInt32) : {UInt32, UInt32, UInt32, UInt32}
        eax = 0_u32
        ebx = 0_u32
        ecx = 0_u32
        edx = 0_u32
        asm("cpuid" : "={eax}"(eax), "={ebx}"(ebx), "={ecx}"(ecx), "={edx}"(edx) : "{eax}"(leaf), "{ecx}"(subleaf))
        {eax, ebx, ecx, edx}
      end

      # The SHA extensions are bit 29 of EBX in leaf 7; the routines also use
      # SSSE3 (`pshufb`, `palignr`) and SSE4.1 (`pblendw`, `pinsrd`,
      # `pextrd`), bits 9 and 19 of ECX in leaf 1.
      private def self.has_sha_extensions? : Bool
        highest_leaf = processor_identification(0_u32, 0_u32)[0]
        return false if highest_leaf < 7

        feature_bits = processor_identification(1_u32, 0_u32)[2]
        extended_feature_bits = processor_identification(7_u32, 0_u32)[1]
        feature_bits.bit(9) == 1 && feature_bits.bit(19) == 1 && extended_feature_bits.bit(29) == 1
      end

      HAS_SHA1_INSTRUCTIONS   = has_sha_extensions?
      HAS_SHA256_INSTRUCTIONS = HAS_SHA1_INSTRUCTIONS
      HAS_SHA512_INSTRUCTIONS = false
    {% else %}
      HAS_SHA1_INSTRUCTIONS   = false
      HAS_SHA256_INSTRUCTIONS = false
      HAS_SHA512_INSTRUCTIONS = false
    {% end %}
  end
end
