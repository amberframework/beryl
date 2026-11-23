# Reads the NIST CAVP ECDSA files of 186-4ecdsatestvectors.zip (`SigVer.rsp`,
# `SigGen.txt`, `KeyPair.rsp`, `PKV.rsp`). A `[P-256,SHA-256]` or `[P-256]`
# line opens a section; each case is a run of `Name = value` lines closed by
# a blank line. Lines of the form `[B.4.2 ...]` describe a method and are
# skipped.
module CavpEcdsaFile
  record TestCase, curve : String, hash : String?, fields : Hash(String, String)

  def self.parse(contents : String) : Array(TestCase)
    list_of_cases = [] of TestCase
    curve = ""
    hash = nil
    fields = Hash(String, String).new
    contents.each_line do |raw_line|
      line = raw_line.strip
      if line.empty?
        list_of_cases << TestCase.new(curve, hash, fields) unless fields.empty?
        fields = Hash(String, String).new
        next
      end
      next if line.starts_with?('#')

      if line.starts_with?('[')
        section = line.strip("[]")
        next if section.starts_with?("B.")
        curve, _, hash_name = section.partition(',')
        hash = hash_name.empty? ? nil : hash_name
        next
      end
      name, _, value = line.partition('=')
      fields[name.strip] = value.strip
    end
    list_of_cases << TestCase.new(curve, hash, fields) unless fields.empty?
    list_of_cases
  end

  # The hex value of a field, left-padded to *bytesize* bytes, or nil when
  # it does not fit (PKV.rsp has coordinates longer than the field).
  def self.fixed_width(hex : String, bytesize : Int32) : Bytes?
    digits = hex.size.odd? ? "0" + hex : hex
    value = digits.hexbytes
    first_nonzero = value.index { |byte| byte != 0 } || value.size
    significant = value[first_nonzero, value.size - first_nonzero]
    return nil if significant.size > bytesize

    padded = Bytes.new(bytesize)
    significant.copy_to(padded[bytesize - significant.size, significant.size])
    padded
  end
end
