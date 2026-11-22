# A statistical check that a function's running time does not depend on its
# secret input, after dudect (Reparaz, Balasch and Verbauwhede, 2017,
# https://eprint.iacr.org/2016/1123).
#
# The function is timed many times on inputs from two classes, picked at
# random for each measurement. If the two classes' timings come from the
# same distribution, Welch's t statistic stays small; dudect reads |t| over
# 4.5 as evidence of a leak. Slow outliers (interrupts, garbage collection)
# are cut at a ladder of percentile thresholds, and the largest |t| over the
# uncut data and every threshold is the result.
class TimingLeakMeasurement
  # dudect's bound: |t| under this shows no leak at this sample size.
  LEAK_THRESHOLD = 4.5

  WARM_UP_MEASUREMENT_COUNT = 10_000
  CROP_THRESHOLD_COUNT      =    100

  # Mean and variance of one class under one threshold, kept as running sums.
  private struct RunningStatistic
    getter count = 0_i64
    @mean = 0.0
    @sum_of_squared_deviations = 0.0

    def add(value : Float64) : Nil
      @count += 1
      delta = value - @mean
      @mean += delta / @count
      @sum_of_squared_deviations += delta * (value - @mean)
    end

    def mean : Float64
      @mean
    end

    def variance : Float64
      @count > 1 ? @sum_of_squared_deviations / (@count - 1) : 0.0
    end
  end

  getter largest_absolute_t = 0.0
  getter measurements_per_class : Int32

  def initialize(@measurements_per_class : Int32, @generator : Random::PCG32)
    # Index 0 holds the uncut data; index n holds what is under threshold n.
    @statistics_of_first_class = Array(RunningStatistic).new(CROP_THRESHOLD_COUNT + 1) { RunningStatistic.new }
    @statistics_of_second_class = Array(RunningStatistic).new(CROP_THRESHOLD_COUNT + 1) { RunningStatistic.new }
    @list_of_crop_thresholds = [] of Float64
  end

  # Times the block once per measurement. *prepare* is given the class
  # (false for the first, true for the second) and puts that class's input
  # in place; only the block that follows is timed.
  def run(prepare : Bool -> Nil, &timed : -> Nil) : Nil
    list_of_warm_up_timings = Array(Float64).new(WARM_UP_MEASUREMENT_COUNT)
    WARM_UP_MEASUREMENT_COUNT.times do
      prepare.call(@generator.next_bool)
      list_of_warm_up_timings << time_once { yield }
    end
    list_of_warm_up_timings.sort!
    @list_of_crop_thresholds = Array(Float64).new(CROP_THRESHOLD_COUNT) do |index|
      percentile = 1.0 - 0.5 ** (10.0 * (index + 1) / CROP_THRESHOLD_COUNT)
      list_of_warm_up_timings[(percentile * (WARM_UP_MEASUREMENT_COUNT - 1)).to_i]
    end

    (2_i64 * @measurements_per_class).times do
      is_second_class = @generator.next_bool
      prepare.call(is_second_class)
      record(is_second_class, time_once { yield })
    end

    @largest_absolute_t = (0..CROP_THRESHOLD_COUNT).max_of do |index|
      welch_t(@statistics_of_first_class[index], @statistics_of_second_class[index]).abs
    end
  end

  def shows_no_leak? : Bool
    @largest_absolute_t < LEAK_THRESHOLD
  end

  private def time_once(&) : Float64
    started_at = Time.instant
    yield
    (Time.instant - started_at).total_nanoseconds
  end

  private def record(is_second_class : Bool, nanoseconds : Float64) : Nil
    list_of_statistics = is_second_class ? @statistics_of_second_class : @statistics_of_first_class
    list_of_statistics[0] = list_of_statistics[0].tap(&.add(nanoseconds))
    @list_of_crop_thresholds.each_with_index do |threshold, index|
      next unless nanoseconds < threshold

      statistic = list_of_statistics[index + 1]
      statistic.add(nanoseconds)
      list_of_statistics[index + 1] = statistic
    end
  end

  private def welch_t(first : RunningStatistic, second : RunningStatistic) : Float64
    # Too few samples under a threshold say nothing either way.
    return 0.0 if first.count < 10_000 || second.count < 10_000

    standard_error = Math.sqrt(first.variance / first.count + second.variance / second.count)
    return 0.0 if standard_error == 0.0

    (first.mean - second.mean) / standard_error
  end
end
