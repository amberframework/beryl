# Counts the published vector cases each algorithm passed, and prints the
# table after the suite so a run shows how much evidence stands behind it.
module VectorCaseCount
  LIST_OF_SOURCES = ["CAVP", "RFC", "Wycheproof"]

  @@count_by_algorithm_and_source = Hash({String, String}, Int32).new(0)
  @@list_of_acceptable_decisions = [] of String

  def self.record(algorithm : String, source : String, count : Int32 = 1) : Nil
    @@count_by_algorithm_and_source[{algorithm, source}] += count
  end

  # Notes how Beryl decided a Wycheproof case marked `acceptable`.
  def self.record_acceptable_decision(description : String) : Nil
    @@list_of_acceptable_decisions << description
  end

  def self.print_table(io : IO) : Nil
    return if @@count_by_algorithm_and_source.empty?

    list_of_algorithms = @@count_by_algorithm_and_source.keys.map(&.[0]).uniq!.sort!
    io.puts
    io.puts "Published vector cases passed"
    io.puts "#{"algorithm".ljust(22)}#{LIST_OF_SOURCES.map(&.rjust(12)).join}#{"total".rjust(12)}"
    grand_total = 0
    list_of_algorithms.each do |algorithm|
      list_of_counts = LIST_OF_SOURCES.map { |source| @@count_by_algorithm_and_source[{algorithm, source}] }
      grand_total += list_of_counts.sum
      io.puts "#{algorithm.ljust(22)}#{list_of_counts.map(&.to_s.rjust(12)).join}#{list_of_counts.sum.to_s.rjust(12)}"
    end
    io.puts "#{"all algorithms".ljust(22)}#{" " * 36}#{grand_total.to_s.rjust(12)}"
    io.puts "A CAVP Monte Carlo checkpoint counts as one case and stands for 1,000 chained digests."
    io.puts "Wycheproof cases marked acceptable: #{@@list_of_acceptable_decisions.size}"
    @@list_of_acceptable_decisions.each { |description| io.puts "  #{description}" }
  end
end

Spec.after_suite { VectorCaseCount.print_table(STDOUT) }
