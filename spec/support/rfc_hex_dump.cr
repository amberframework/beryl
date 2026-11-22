# Reads the byte strings RFC 8439 and the XChaCha draft print in their
# examples. Three layouts appear:
#
#     000  80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f  ................
#
#     FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
#
#     4c616469657320616e642047656e746c656d656e206f662074686520636c6173
#
# A value starts on the line after its label and runs until a line that is
# none of the three; blank lines and the page break of a text RFC (footer,
# form feed, header) are stepped over while a dump with offsets is still
# due its next offset.
module RfcHexDump
  private OFFSET_LINE = /\A\s*(\d{3,4})\s{2}((?:[0-9a-f]{2}\s)*[0-9a-f]{2})(?:\s{2,}.*)?\z/
  private SPACED_LINE = /\A\s*((?:[0-9A-Fa-f]{2}\s)*[0-9A-Fa-f]{2})\s*\z/
  private SOLID_LINE  = /\A\s*((?:[0-9a-f]{2}){2,})\s*\z/
  private COLON_LINE  = /\A\s*((?:[0-9a-f]{2}:)+[0-9a-f]{2})\s*\z/
  private PAGE_BREAK  = /\[Page \d+\]\s*\z|\A\f|\ARFC \d+ |\AInternet-Draft /

  # Returns the lines of *text* from the first line matching *from* (looked
  # for after the *occurrence*-th match, counting from 1) up to the first
  # later line matching *to*.
  def self.section(text : String, from : Regex, to : Regex, occurrence : Int32 = 1) : Array(String)
    list_of_lines = text.lines
    list_of_starts = list_of_lines.each_index.select { |index| list_of_lines[index].matches?(from) }.to_a
    first_line = list_of_starts[occurrence - 1]? || raise "no line matches #{from.source} (occurrence #{occurrence})"
    last_line = (first_line + 1...list_of_lines.size).find { |index| list_of_lines[index].matches?(to) } || list_of_lines.size
    list_of_lines[first_line...last_line]
  end

  # Returns every value in *list_of_lines* that follows a line matching
  # *label*, in order.
  def self.values_after(list_of_lines : Array(String), label : Regex) : Array(Bytes)
    list_of_values = [] of Bytes
    list_of_lines.each_with_index do |line, index|
      list_of_values << value_from(list_of_lines, index + 1) if line.matches?(label)
    end
    list_of_values
  end

  # Returns the value that starts at line *first_line*.
  def self.value_from(list_of_lines : Array(String), first_line : Int32) : Bytes
    hexadecimal = String::Builder.new
    bytes_read = 0
    has_started = false
    is_offset_dump = false
    index = first_line
    while index < list_of_lines.size
      line = list_of_lines[index]
      index += 1
      if offset_match = OFFSET_LINE.match(line)
        raise "a dump continues at offset #{offset_match[1]}, #{bytes_read} bytes were read" unless offset_match[1].to_i == bytes_read
        digits = offset_match[2].delete(' ')
        hexadecimal << digits
        bytes_read += digits.size // 2
        has_started = true
        is_offset_dump = true
      elsif !is_offset_dump && (plain_match = SPACED_LINE.match(line) || SOLID_LINE.match(line) || COLON_LINE.match(line))
        digits = plain_match[1].delete(" :").downcase
        hexadecimal << digits
        bytes_read += digits.size // 2
        has_started = true
      elsif line.blank? || line.matches?(PAGE_BREAK)
        # A dump with offsets may continue on the next page; any other
        # layout ends at the first blank line.
        break if has_started && !is_offset_dump
        break if has_started && is_offset_dump && bytes_read % 16 != 0
      else
        break
      end
    end
    hexadecimal.to_s.hexbytes
  end
end
