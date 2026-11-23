# Writes DER for the specs: enough to build keys, extensions and hostile
# encodings by hand.
module DerWriter
  def self.element(tag : UInt8, content : Bytes) : Bytes
    io = IO::Memory.new
    io.write_byte(tag)
    write_length(io, content.size)
    io.write(content)
    io.to_slice
  end

  def self.sequence(*parts : Bytes) : Bytes
    element(0x30_u8, concat(parts.to_a))
  end

  def self.integer(magnitude : Bytes) : Bytes
    trimmed = magnitude
    while trimmed.size > 1 && trimmed[0] == 0
      trimmed = trimmed[1, trimmed.size - 1]
    end
    content = trimmed[0] & 0x80 != 0 ? concat([Bytes[0], trimmed]) : trimmed
    element(0x02_u8, content)
  end

  def self.small_integer(value : Int32) : Bytes
    integer(Bytes[value.to_u8])
  end

  def self.octet_string(content : Bytes) : Bytes
    element(0x04_u8, content)
  end

  def self.object_identifier(dotted : String) : Bytes
    element(0x06_u8, Beryl::Encoding::DER::ObjectIdentifier.parse(dotted).encoded)
  end

  def self.context(number : Int32, content : Bytes) : Bytes
    element((0xa0 | number).to_u8, content)
  end

  def self.concat(list_of_parts : Array(Bytes)) : Bytes
    io = IO::Memory.new
    list_of_parts.each { |part| io.write(part) }
    io.to_slice
  end

  private def self.write_length(io : IO, length : Int32) : Nil
    if length < 0x80
      io.write_byte(length.to_u8)
    elsif length < 0x100
      io.write_byte(0x81_u8)
      io.write_byte(length.to_u8)
    else
      io.write_byte(0x82_u8)
      io.write_byte((length >> 8).to_u8)
      io.write_byte((length & 0xff).to_u8)
    end
  end
end
