# Reads the test cases that RFC 4231 and RFC 5869 print as labeled fields:
#
#     Key =          0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
#                    0b0b0b0b                          (20 bytes)
#     HMAC-SHA-224 = 896fb1128abbdf196832107cd49df33f
#
# A field starts at a line that opens with one of the known labels and runs
# over the hexadecimal lines that follow it; any other line closes it.
module RfcLabeledFields
  # One test case: the raw text of each field by label. A hexadecimal field
  # is the concatenation of its lines with the `0x` prefix and the trailing
  # remarks removed.
  alias TestCase = Hash(String, String)

  # Splits *rfc_text* into test cases at each line matching *case_heading*
  # and collects the fields named in *list_of_labels* inside each.
  def self.parse(rfc_text : String, case_heading : Regex, list_of_labels : Array(String)) : Array(TestCase)
    label_line = /\A\s+(#{list_of_labels.map { |label| Regex.escape(label) }.join('|')})\s*=?\s+(.*)\z/
    continuation_line = /\A\s+((?:[0-9a-f]{2})+)(?:\s+\(.*\))?\s*\z/
    list_of_test_cases = [] of TestCase
    current_test_case = nil
    current_label = nil

    rfc_text.each_line do |line|
      if line.matches?(case_heading)
        current_test_case = TestCase.new
        list_of_test_cases << current_test_case
        current_label = nil
        next
      end
      next unless current_test_case

      if label_match = label_line.match(line)
        current_label = label_match[1]
        current_test_case[current_label] = leading_value(label_match[2])
      elsif current_label && (continuation_match = continuation_line.match(line))
        current_test_case[current_label] += continuation_match[1]
      else
        current_label = nil
      end
    end
    list_of_test_cases
  end

  # Returns the hexadecimal digits at the start of *field_text* (after an
  # optional `0x`), or the text itself when it does not start with any.
  private def self.leading_value(field_text : String) : String
    hexadecimal_match = /\A(?:0x)?((?:[0-9a-f]{2})+)(?:\s|\z)/.match(field_text)
    return hexadecimal_match[1] if hexadecimal_match

    field_text.strip
  end
end
