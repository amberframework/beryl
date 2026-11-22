require "digest/sha256"
require "json"

# Reads the published test vectors under `spec/vectors`, refusing any file
# whose sha256 differs from its pin in `spec/vectors/manifest.json`.
#
# The check uses the standard library's SHA-256 (OpenSSL), so the hash under
# test never vouches for its own test data.
module VectorFile
  VECTOR_ROOT = Path[__DIR__].parent / "vectors"

  class PinMismatch < Exception
  end

  struct PinnedFile
    include JSON::Serializable

    getter stored_path : String = ""
    getter sha256 : String = ""
  end

  struct PinnedDownload
    include JSON::Serializable

    getter source : String = ""
    getter url : String = ""
    getter sha256 : String = ""
    getter pinned_at : String = ""
    getter list_of_files : Array(PinnedFile) = [] of PinnedFile
  end

  struct Manifest
    include JSON::Serializable

    getter list_of_downloads : Array(PinnedDownload) = [] of PinnedDownload

    def list_of_pinned_files : Array(PinnedFile)
      list_of_downloads.flat_map(&.list_of_files)
    end
  end

  class_getter manifest : Manifest { Manifest.from_json(File.read(VECTOR_ROOT / "manifest.json")) }

  # Returns the contents of the vector file at *stored_path* (relative to
  # *vector_root*) after checking its sha256 against the manifest.
  def self.read(stored_path : String, vector_root : Path = VECTOR_ROOT) : String
    pinned_file = manifest.list_of_pinned_files.find { |candidate| candidate.stored_path == stored_path }
    unless pinned_file
      raise PinMismatch.new("spec/vectors/#{stored_path} has no sha256 pin in spec/vectors/manifest.json")
    end

    contents = File.read(vector_root / stored_path)
    observed_sha256 = Digest::SHA256.hexdigest(contents)
    unless observed_sha256 == pinned_file.sha256
      raise PinMismatch.new(
        "spec/vectors/#{stored_path} does not match its pin: sha256 is #{observed_sha256}, " \
        "spec/vectors/manifest.json pins #{pinned_file.sha256}"
      )
    end
    contents
  end
end
