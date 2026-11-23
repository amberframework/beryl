# Reads the test vectors that RFC 7748, RFC 8032 and RFC 6979 print in
# their text, after removing the page breaks (form feeds and the header and
# footer lines around them).
module RfcTextVectors
  PAGE_LINE = /\A(?:RFC \d+ .*\d{4}\s*\z|.*\[Page \d+\]\s*\z|\f)/

  def self.lines_without_page_breaks(rfc_text : String) : Array(String)
    rfc_text.lines.reject { |line| line.matches?(PAGE_LINE) || line.includes?('\f') }
  end

  # Returns the lines from the first one matching *start* up to (not
  # including) the first later one matching *stop*.
  def self.section(rfc_text : String, start : Regex, stop : Regex) : Array(String)
    list_of_lines = lines_without_page_breaks(rfc_text)
    first = list_of_lines.index { |line| line.matches?(start) } || raise "section #{start} not found"
    last = list_of_lines.index(first + 1) { |line| line.matches?(stop) } || list_of_lines.size
    list_of_lines[first...last]
  end

  # Returns the hexadecimal lines that follow the first line matching
  # *label* in *list_of_lines*, joined, up to the first line that is not
  # hexadecimal.
  def self.hex_after(list_of_lines : Array(String), label : Regex) : String
    index = list_of_lines.index { |line| line.matches?(label) } || raise "label #{label} not found"
    hex = ""
    list_of_lines[(index + 1)..].each do |line|
      stripped = line.strip
      next if stripped.empty? && hex.empty?
      break unless stripped.matches?(/\A[0-9a-fA-F]+\z/)
      hex += stripped
    end
    hex.downcase
  end

  # RFC 8032 §7.1: each "-----TEST" block's secret key, public key, message
  # and signature.
  record Ed25519Case, name : String, secret_key : Bytes, public_key : Bytes, message : Bytes, signature : Bytes

  def self.rfc8032_ed25519_cases(rfc_text : String) : Array(Ed25519Case)
    list_of_lines = section(rfc_text, /\A7\.1\.\s+Test Vectors for Ed25519/, /\A7\.2\./)
    list_of_cases = [] of Ed25519Case
    block_starts = list_of_lines.each_index.select { |index| list_of_lines[index].includes?("-----TEST") }.to_a
    block_starts.each_with_index do |start, block_number|
      stop = block_starts[block_number + 1]? || list_of_lines.size
      block = list_of_lines[start...stop]
      fields = Hash(String, String).new
      label = nil
      message_bytesize = 0
      block[1..].each do |line|
        stripped = line.strip
        if stripped.matches?(/\A[A-Z][A-Z ]+(?:\(length (\d+) bytes?\))?:\z/)
          label = stripped.split(/[ (:]/).first
          label = stripped.starts_with?("SECRET") ? "SECRET" : stripped.starts_with?("PUBLIC") ? "PUBLIC" : label
          if length_match = stripped.match(/\(length (\d+) bytes?\)/)
            message_bytesize = length_match[1].to_i
          end
          fields[label] = ""
        elsif (current = label) && stripped.matches?(/\A[0-9a-f]+\z/)
          fields[current] += stripped
        end
      end
      message = fields["MESSAGE"].hexbytes
      raise "RFC 8032 #{block[0].strip}: message is #{message.size} bytes, the text says #{message_bytesize}" unless message.size == message_bytesize
      list_of_cases << Ed25519Case.new(block[0].strip.lchop("-----"), fields["SECRET"].hexbytes, fields["PUBLIC"].hexbytes, message, fields["SIGNATURE"].hexbytes)
    end
    list_of_cases
  end

  # RFC 6979 A.2.5 and A.2.6: the key pair, and for each hash and message
  # the nonce k and the signature (r, s).
  record DeterministicSignatureCase, hash : String, message : String, k : String, r : String, s : String
  record DeterministicSignatureKey, private_key : String, public_x : String, public_y : String,
    list_of_cases : Array(DeterministicSignatureCase)

  def self.rfc6979_cases(rfc_text : String, section_start : Regex, section_stop : Regex) : DeterministicSignatureKey
    list_of_lines = section(rfc_text, section_start, section_stop)
    values = [] of {String, String}
    current_name = nil
    current_value = ""
    current_heading = nil
    list_of_cases = [] of DeterministicSignatureCase
    pending = Hash(String, String).new
    flush = -> do
      if name = current_name
        values << {name, current_value.downcase}
        pending[name] = current_value.downcase
      end
      current_name = nil
      current_value = ""
    end
    list_of_lines.each do |line|
      stripped = line.strip
      if heading_match = stripped.match(/\AWith (SHA-\d+), message = "(\w+)":\z/)
        flush.call
        current_heading = {heading_match[1], heading_match[2]}
        pending.clear
      elsif value_match = stripped.match(/\A(x|Ux|Uy|k|r|s) = ([0-9A-F]+)\z/)
        flush.call
        current_name = value_match[1]
        current_value = value_match[2]
      elsif current_name && stripped.matches?(/\A[0-9A-F]+\z/)
        current_value += stripped
      else
        flush.call
      end
      if (heading = current_heading) && pending.has_key?("s") && current_name.nil?
        list_of_cases << DeterministicSignatureCase.new(heading[0], heading[1], pending["k"], pending["r"], pending["s"])
        current_heading = nil
        pending.clear
      end
    end
    flush.call
    if (heading = current_heading) && pending.has_key?("s")
      list_of_cases << DeterministicSignatureCase.new(heading[0], heading[1], pending["k"], pending["r"], pending["s"])
    end
    lookup = values.to_h
    DeterministicSignatureKey.new(lookup["x"], lookup["Ux"], lookup["Uy"], list_of_cases)
  end
end
