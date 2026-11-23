# The Certificate Transparency corpus (scripts/fetch_certificate_corpus.rb)
# and the mutations the certificate differential and the fuzz campaign
# apply to it.
module CertificateCorpus
  PATH = Path[__DIR__].parent / "vectors" / "corpus" / "ct-nimbus2026.bin"

  # One log entry: 0 for an X.509 entry, 1 for a precertificate; the log
  # time; the logged certificate first and its chain after it.
  record Entry, entry_type : UInt8, timestamp : Time, list_of_certificates : Array(Bytes)

  def self.read(path : Path = PATH) : Array(Entry)
    bytes = File.read(path).to_slice
    raise "not a BERYLCT1 corpus" unless String.new(bytes[0, 8]) == "BERYLCT1"
    io = IO::Memory.new(bytes[8, bytes.size - 8])
    list_of_entries = [] of Entry
    while io.pos < io.size
      entry_type = io.read_byte || raise "truncated corpus"
      milliseconds = io.read_bytes(UInt64, IO::ByteFormat::BigEndian)
      count = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      list_of_certificates = Array(Bytes).new(count.to_i) do
        length = io.read_bytes(UInt32, IO::ByteFormat::BigEndian)
        certificate = Bytes.new(length)
        io.read_fully(certificate)
        certificate
      end
      list_of_entries << Entry.new(entry_type, Time.unix_ms(milliseconds.to_i64), list_of_certificates)
    end
    list_of_entries
  end

  # Every distinct certificate of the corpus.
  def self.distinct_certificates(list_of_entries : Array(Entry)) : Array(Bytes)
    unique = Set(Bytes).new
    list_of_entries.each { |entry| entry.list_of_certificates.each { |certificate| unique << certificate } }
    unique.to_a
  end

  # The byte ranges of every element in *der* (offset of the header,
  # whole length), found by a lenient walk that stops at anything odd.
  def self.list_of_elements(der : Bytes, offset : Int32 = 0, finish : Int32 = der.size, depth : Int32 = 0, into list : Array({Int32, Int32}) = [] of {Int32, Int32}) : Array({Int32, Int32})
    position = offset
    while position + 2 <= finish && depth < 12
      tag = der[position]
      length_byte = der[position + 1]
      header = 2
      length = length_byte.to_i32
      if length_byte & 0x80 != 0
        count = (length_byte & 0x7f).to_i32
        return list if count == 0 || count > 3 || position + 2 + count > finish
        length = 0
        count.times { |index| length = (length << 8) | der[position + 2 + index] }
        header = 2 + count
      end
      break if position + header + length > finish
      list << {position, header + length}
      list_of_elements(der, position + header, position + header + length, depth + 1, list) if tag & 0x20 != 0
      position += header + length
    end
    list
  end

  LIST_OF_TAGS = {0x01_u8, 0x02_u8, 0x03_u8, 0x04_u8, 0x05_u8, 0x06_u8, 0x0c_u8, 0x13_u8, 0x16_u8, 0x17_u8, 0x18_u8,
                  0x30_u8, 0x31_u8, 0x80_u8, 0x81_u8, 0x82_u8, 0x86_u8, 0x87_u8, 0xa0_u8, 0xa1_u8, 0xa3_u8, 0xa4_u8}

  # One mutation of *der*, in the manner of Frankencert: a bit flipped, a
  # byte set, inserted or deleted, a length or a tag changed, a length
  # pushed into its long form, or an element replaced by one from *donor*.
  def self.mutate(der : Bytes, donor : Bytes, generator : Random) : Bytes
    return Bytes[generator.rand(256).to_u8] if der.empty?

    copy = der.dup
    case generator.rand(8)
    when 0
      copy[generator.rand(copy.size)] ^= (1_u8 << generator.rand(8))
      copy
    when 1
      copy[generator.rand(copy.size)] = generator.rand(256).to_u8
      copy
    when 2
      index = generator.rand(copy.size + 1)
      Bytes.new(copy.size + 1) { |position| position < index ? copy[position] : (position == index ? generator.rand(256).to_u8 : copy[position - 1]) }
    when 3
      index = generator.rand(copy.size)
      Bytes.new(copy.size - 1) { |position| position < index ? copy[position] : copy[position + 1] }
    when 4
      elements = list_of_elements(copy)
      return copy if elements.empty?
      offset, _ = elements[generator.rand(elements.size)]
      copy[offset + 1] = (copy[offset + 1].to_i32 + generator.rand(-2..2)).clamp(0, 255).to_u8
      copy
    when 5
      elements = list_of_elements(copy)
      return copy if elements.empty?
      offset, _ = elements[generator.rand(elements.size)]
      copy[offset] = LIST_OF_TAGS.sample(generator)
      copy
    when 6
      # A short length written in a long form (0x81 nn), which DER forbids.
      elements = list_of_elements(copy)
      return copy if elements.empty?
      offset, _ = elements[generator.rand(elements.size)]
      length_byte = copy[offset + 1]
      return copy if length_byte >= 0x80
      io = IO::Memory.new
      io.write(copy[0, offset + 1])
      io.write_byte(0x81_u8)
      io.write(copy[offset + 1, copy.size - offset - 1])
      io.to_slice
    else
      elements = list_of_elements(copy)
      donor_elements = list_of_elements(donor)
      return copy if elements.empty? || donor_elements.empty?
      offset, length = elements[generator.rand(elements.size)]
      donor_offset, donor_length = donor_elements[generator.rand(donor_elements.size)]
      io = IO::Memory.new
      io.write(copy[0, offset])
      io.write(donor[donor_offset, donor_length])
      io.write(copy[offset + length, copy.size - offset - length])
      io.to_slice
    end
  end
end
