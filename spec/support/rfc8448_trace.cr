# Reads the example handshakes of RFC 8448 into steps and fields.
#
# A step is a line such as
#
#     {server}  derive secret "tls13 c hs traffic":
#
# and its fields are the labeled byte strings below it:
#
#     expanded (32 octets):  b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e
#        2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21
#
# A field runs over its continuation lines until it holds the number of
# octets its label states, stepping over the page breaks of the text RFC.
module Rfc8448Trace
  PATH = "#{__DIR__}/../vectors/rfc/rfc8448.txt"

  private STEP_LINE        = /\A   \{(client|server)\}  (.*?):?\s*\z/
  private FIELD_LINE       = /\A      ([A-Za-z][A-Za-z0-9 \-]*?) \((\d+) octets\):\s*(.*)\z/
  private HEXADECIMAL_LINE = /\A\s+((?:[0-9a-f]{2} )*[0-9a-f]{2})\s*\z/
  private SECTION_LINE     = /\A(\d+)\.  \S/
  private PAGE_BREAK       = /\[Page \d+\]\s*\z|\A\f|\ARFC 8448 /

  # One step of a trace: who performs it, what it is, and its fields in
  # order of appearance (a label may repeat, as "PRK" does).
  class Step
    getter actor : String
    getter title : String
    getter list_of_fields = [] of {String, Bytes}

    def initialize(@actor : String, @title : String)
    end

    # Returns the first field labeled *label*.
    def field(label : String) : Bytes
      @list_of_fields.find { |entry| entry[0] == label }.try(&.[1]) || raise "step #{@actor} #{@title.inspect} has no field #{label.inspect}"
    end
  end

  @@list_of_steps_by_section = {} of Int32 => Array(Step)

  # Returns the steps of section *number* (3: simple 1-RTT, 4: resumed
  # 0-RTT, 5: HelloRetryRequest, 6: client authentication, 7:
  # compatibility mode).
  def self.section(number : Int32) : Array(Step)
    load if @@list_of_steps_by_section.empty?
    @@list_of_steps_by_section[number]? || raise "RFC 8448 has no section #{number}"
  end

  # Returns the *occurrence*-th step of section *number* done by *actor*
  # whose title starts with *title* and that prints fields (a step
  # marked "same as" the other side prints none and is passed over).
  def self.step(number : Int32, actor : String, title : String, occurrence : Int32 = 1) : Step
    list_of_matches = section(number).select do |candidate|
      candidate.actor == actor && candidate.title.starts_with?(title) && !candidate.list_of_fields.empty?
    end
    list_of_matches[occurrence - 1]? || raise "section #{number} has no step #{actor} #{title.inspect} (occurrence #{occurrence})"
  end

  # Returns the field *label* of that step.
  def self.field(number : Int32, actor : String, title : String, label : String, occurrence : Int32 = 1) : Bytes
    step(number, actor, title, occurrence).field(label)
  end

  private def self.load : Nil
    list_of_lines = File.read(PATH).lines
    current_section = 0
    current_step = nil
    index = 0
    while index < list_of_lines.size
      line = list_of_lines[index]
      index += 1
      if section_match = SECTION_LINE.match(line)
        current_section = section_match[1].to_i
        @@list_of_steps_by_section[current_section] ||= [] of Step
        current_step = nil
      elsif step_match = STEP_LINE.match(line)
        current_step = Step.new(step_match[1], step_match[2].sub(/\s*\(.*\z/, "").rstrip(':'))
        (@@list_of_steps_by_section[current_section] ||= [] of Step) << current_step
      elsif (field_match = FIELD_LINE.match(line)) && current_step
        expected_bytesize = field_match[2].to_i
        hexadecimal = String::Builder.new
        first_part = field_match[3].strip
        bytes_read = 0
        if first_part.matches?(/\A(?:[0-9a-f]{2} ?)+\z/)
          hexadecimal << first_part.delete(' ')
          bytes_read = first_part.delete(' ').size // 2
        end
        while bytes_read < expected_bytesize && index < list_of_lines.size
          continuation = list_of_lines[index]
          if hexadecimal_match = HEXADECIMAL_LINE.match(continuation)
            digits = hexadecimal_match[1].delete(' ')
            hexadecimal << digits
            bytes_read += digits.size // 2
            index += 1
          elsif continuation.strip.empty? || continuation.matches?(PAGE_BREAK)
            index += 1
          else
            break
          end
        end
        raise "field #{field_match[1]} of #{current_step.title} holds #{bytes_read} octets, not #{expected_bytesize}" unless bytes_read == expected_bytesize
        current_step.list_of_fields << {field_match[1], hexadecimal.to_s.hexbytes}
      end
    end
  end
end
