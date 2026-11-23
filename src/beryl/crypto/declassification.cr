module Beryl::Crypto
  # :nodoc:
  #
  # The places where a value computed from secrets is allowed to decide what
  # the code does next. There are two kinds: the verdict on a message that
  # arrived from outside (its tag matched or not, its padding was well
  # formed or not), and a result about to be returned (a signature). The
  # caller learns either anyway, since it is the return value.
  #
  # Every such decision passes through this module, so the constant-time
  # checks can tell an intended verdict from a leak, and a reader can list
  # them with one search.
  module Declassification
    # Returns *verdict* unchanged. The value passes through an empty piece
    # of inline assembly, so the optimizer cannot see through the call or
    # remove it, and the call is still there in the compiled code.
    @[NoInline]
    def self.reveal(verdict : Bool) : Bool
      reveal(verdict ? 1_u32 : 0_u32) == 1_u32
    end

    # Returns *published* unchanged: bytes computed from secrets that are
    # about to be handed out, such as the two halves of a signature, on
    # their way into code written for public data (the signature encoder).
    @[NoInline]
    def self.reveal(published : Bytes) : Bytes
      published
    end

    # Returns *padding_bytesize* unchanged: the number of padding bytes at the
    # end of a decrypted message, or zero when the padding is malformed. The
    # caller learns it from the length of the plaintext it gets back.
    @[NoInline]
    def self.reveal(padding_bytesize : UInt32) : UInt32
      revealed = 0_u32
      asm("" : "=r"(revealed) : "0"(padding_bytesize) :: "volatile")
      revealed
    end
  end
end
