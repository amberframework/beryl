require "./spec_helper"
require "file_utils"

describe VectorFile do
  it "has every pinned file on disk with the pinned sha256" do
    list_of_pinned_files = VectorFile.manifest.list_of_pinned_files
    list_of_pinned_files.should_not be_empty
    list_of_pinned_files.each { |pinned_file| VectorFile.read(pinned_file.stored_path) }
  end

  it "lists every pinned file, its download and its sha256 in SOURCES.md" do
    sources = File.read(VectorFile::VECTOR_ROOT / "SOURCES.md")
    VectorFile.manifest.list_of_downloads.each do |download|
      sources.should contain(download.url)
      sources.should contain(download.sha256)
      sources.should contain(download.pinned_at)
      download.list_of_files.each do |pinned_file|
        sources.should contain("`spec/vectors/#{pinned_file.stored_path}` sha256 `#{pinned_file.sha256}`")
      end
    end
  end

  it "refuses a file that differs from its pin by one byte, naming the file" do
    stored_path = "rfc/rfc6070.txt"
    altered_root = Path[File.tempname("beryl-altered-vectors")]
    begin
      Dir.mkdir_p(altered_root / "rfc")
      contents = VectorFile.read(stored_path).to_slice.dup
      contents[100] ^= 0x01_u8
      File.write(altered_root / stored_path, contents)

      expect_raises(VectorFile::PinMismatch, "spec/vectors/rfc/rfc6070.txt does not match its pin") do
        VectorFile.read(stored_path, vector_root: altered_root)
      end
    ensure
      FileUtils.rm_rf(altered_root.to_s)
    end
  end

  it "refuses a file that has no pin" do
    expect_raises(VectorFile::PinMismatch, "has no sha256 pin") do
      VectorFile.read("rfc/rfc0000.txt")
    end
  end
end
