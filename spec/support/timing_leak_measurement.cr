# A statistical check that a function's running time does not depend on its
# secret input, after dudect (Reparaz, Balasch and Verbauwhede, 2017,
# https://eprint.iacr.org/2016/1123).
#
# The function is timed many times on inputs from two classes, picked at
# random for each measurement. Inputs are laid out a batch at a time before
# any of the batch is timed, and the step that runs between two timed calls
# is the same code for both classes, so the classes differ in nothing but
# the secret bytes the timed call reads. If the two classes' timings come from the
# same distribution, Welch's t statistic stays small; dudect reads |t| over
# 4.5 as evidence of a leak. Slow outliers (interrupts, garbage collection)
# are cut at a ladder of percentile thresholds, and the largest |t| over the
# uncut data and every threshold is the result.
class TimingLeakMeasurement
  # dudect's bound: |t| under this shows no leak at this sample size.
  LEAK_THRESHOLD = 4.5

  WARM_UP_MEASUREMENT_COUNT = 10_240
  BATCH_SIZE                =  1_024
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

  # Times the block once per measurement, in batches of `BATCH_SIZE`.
  #
  # *fill_batch* is given the class of each slot of the coming batch (false
  # for the first class, true for the second) and lays out every slot's
  # input. *prepare* is given a slot number and readies the timed call; it
  # must do the same work for both classes. Only the block, which is given
  # the slot number, is timed.
  def run(fill_batch : Array(Bool) -> Nil, prepare : Int32 -> Nil, &timed : Int32 -> Nil) : Nil
    list_of_classes = Array(Bool).new(BATCH_SIZE, false)
    list_of_warm_up_timings = Array(Float64).new(WARM_UP_MEASUREMENT_COUNT)
    (WARM_UP_MEASUREMENT_COUNT // BATCH_SIZE).times do
      time_one_batch(list_of_classes, fill_batch, prepare, timed) { |slot, nanoseconds| list_of_warm_up_timings << nanoseconds }
    end
    list_of_warm_up_timings.sort!
    @list_of_crop_thresholds = Array(Float64).new(CROP_THRESHOLD_COUNT) do |index|
      percentile = 1.0 - 0.5 ** (10.0 * (index + 1) / CROP_THRESHOLD_COUNT)
      list_of_warm_up_timings[(percentile * (list_of_warm_up_timings.size - 1)).to_i]
    end

    (2_i64 * @measurements_per_class // BATCH_SIZE).times do
      time_one_batch(list_of_classes, fill_batch, prepare, timed) { |slot, nanoseconds| record(list_of_classes[slot], nanoseconds) }
    end

    @largest_absolute_t = (0..CROP_THRESHOLD_COUNT).max_of do |index|
      welch_t(@statistics_of_first_class[index], @statistics_of_second_class[index]).abs
    end
  end

  private def time_one_batch(list_of_classes : Array(Bool), fill_batch : Array(Bool) -> Nil, prepare : Int32 -> Nil,
                             timed : Int32 -> Nil, & : Int32, Float64 -> Nil) : Nil
    BATCH_SIZE.times { |slot| list_of_classes[slot] = @generator.next_bool }
    fill_batch.call(list_of_classes)
    BATCH_SIZE.times do |slot|
      prepare.call(slot)
      started_at = Time.instant
      timed.call(slot)
      nanoseconds = (Time.instant - started_at).total_nanoseconds
      yield slot, nanoseconds
    end
  end

  # The first class's mean time minus the second's, over the uncut data, in
  # nanoseconds: negative when the first (fixed) class runs faster.
  def mean_difference_nanoseconds : Float64
    @statistics_of_first_class[0].mean - @statistics_of_second_class[0].mean
  end

  def shows_no_leak? : Bool
    @largest_absolute_t < LEAK_THRESHOLD
  end

  private def record(is_second_class : Bool, nanoseconds : Float64) : Nil
    list_of_statistics = is_second_class ? @statistics_of_second_class : @statistics_of_first_class
    uncut = list_of_statistics[0]
    uncut.add(nanoseconds)
    list_of_statistics[0] = uncut
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
