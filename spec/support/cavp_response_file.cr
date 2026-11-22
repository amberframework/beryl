# Reads NIST CAVP response files (`.rsp`): comment lines start with `#`,
# a `[L = 32]` line opens a section, and each case is a run of `Name = value`
# lines closed by a blank line.
module CavpResponseFile
  # One case: its fields by name, plus the section values in force (`L`).
  alias Record = Hash(String, String)

  def self.parse(contents : String) : Array(Record)
    list_of_records = [] of Record
    section_fields = Record.new
    current_record = Record.new

    contents.each_line do |raw_line|
      line = raw_line.strip
      if line.empty?
        list_of_records << section_fields.merge(current_record) unless current_record.empty?
        current_record = Record.new
        next
      end
      next if line.starts_with?('#')

      if line.starts_with?('[')
        field_name, _, field_value = line.strip("[]").partition('=')
        section_fields[field_name.strip] = field_value.strip
        next
      end

      field_name, _, field_value = line.partition('=')
      current_record[field_name.strip] = field_value.strip
    end
    list_of_records << section_fields.merge(current_record) unless current_record.empty?
    list_of_records
  end
end
