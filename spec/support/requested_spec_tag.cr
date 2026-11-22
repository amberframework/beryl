# Tells whether this run was started with `--tag <tag>`.
#
# The long-running specs (the differential against libcrypto, the timing
# check, the multi-million-iteration PBKDF2 vectors) define their examples
# only when their tag is asked for, so a plain `crystal-alpha spec` stays a
# quick suite.
module RequestedSpecTag
  @@list_of_arguments = [] of String

  # Keeps a copy of the command line before the spec runner consumes it.
  def self.remember(list_of_arguments : Array(String)) : Nil
    @@list_of_arguments = list_of_arguments.dup
  end

  def self.includes?(tag : String) : Bool
    @@list_of_arguments.each_with_index.any? do |argument, index|
      argument == "--tag=#{tag}" || (argument == "--tag" && @@list_of_arguments[index + 1]? == tag)
    end
  end
end
