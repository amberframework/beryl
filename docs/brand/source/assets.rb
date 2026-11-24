#!/usr/bin/ruby
# Builds Beryl's README art in light and dark: badges, the public-key and
# certificate speed chart, the verification panel and the Amber lockup.
# Every number below is quoted from the repo's docs: docs/crypto/public-key.md
# (milestone F3b: curves at commit e7a0765, RSA at commit 05d1481, Apple M4)
# and docs/certificates.md (milestone F3b, commit 05d1481, Apple M4), and the
# test counts from the same documents.
# Usage: assets.rb <art-dir> <out-dir> [chart ...]
#   With chart names (badges, public-key-speed, verified, amber-lockup) only
#   those are written.
require_relative 'beryl_kit'
include BerylKit

ART = ARGV[0] or abort 'usage: assets.rb <art-dir> <out-dir> [chart ...]'
OUT = ARGV[1] or abort 'usage: assets.rb <art-dir> <out-dir> [chart ...]'
LIST_OF_CHARTS = ARGV[2..]

# ---------------------------------------------------------------- badges
def badges(palette)
  plates = [
    ['PURE CRYSTAL', palette[:accent]],
    ['NO OPENSSL LINKED', palette[:text]],
    ['DIFFERENTIAL AGAINST OPENSSL', palette[:accent]],
    ['CONSTANT-TIME GATES', palette[:text]],
    ['CRYSTAL 1.21+', palette[:accent]],
    ['MIT', palette[:muted]]
  ]
  gap = 10
  size = 12.5
  pad = 16
  widths = plates.map { |label, _| text_width('Manrope-700', size, 0.1, label) + pad * 2 }
  total = widths.inject(:+) + gap * (plates.size - 1)
  height = 34
  parts = []
  cursor = 0.0
  plates.each_with_index do |(label, color), index|
    width = widths[index]
    parts << %(<rect x="#{(cursor + 0.75).round(2)}" y=".75" width="#{(width - 1.5).round(2)}" height="#{height - 1.5}" rx="#{(height - 1.5) / 2}" fill="#{palette[:panel]}" stroke="#{color}" stroke-opacity=".7" stroke-width="1.2"/>)
    parts << text_at('Manrope-700', size, 0.1, label, left: cursor + width / 2.0, baseline: 21.5, fill: color, anchor: :middle)
    cursor += width + gap
  end
  svg_open(total.ceil, height, 'Beryl at a glance',
           'Pure Crystal. No OpenSSL linked. Differential tests against OpenSSL. Constant-time gates. Crystal 1.21 or later. MIT license.') +
    parts.join("\n") + '</svg>'
end

# ---------------------------------------------------------------- chart frame
def chart_frame(palette, width, height, title, subtitle_lines)
  body = []
  body << %(<rect x=".75" y=".75" width="#{width - 1.5}" height="#{height - 1.5}" rx="18" fill="#{palette[:panel]}" stroke="#{palette[:panel_edge]}" stroke-width="1.5"/>)
  body << text_at('Fraunces-600', 34, -0.005, title, left: 48, baseline: 68, fill: palette[:text])
  subtitle_lines.each_with_index do |line, index|
    body << text_at('Manrope-400', 19, 0, line, left: 49, baseline: 104 + index * 27, fill: palette[:muted])
  end
  body
end

# ---------------------------------------------------------------- public-key speed
# [group, operation, ratio]: ratio > 0 is "N× as fast", ratio < 0 is "N× slower".
# Median of ten rounds, Beryl against libcrypto, from the docs' tables.
SPEED_GROUPS = [
  ['Curves', 'docs/crypto/public-key.md, Apple M4, commit e7a0765', [
    ['X25519 key generation', 1.21],
    ['X25519 shared secret', 1.034],
    ['Ed25519 key generation', 1.23],
    ['Ed25519 sign', 1.15],
    ['Ed25519 verify', 1.34],
    ['P-256 key generation', 1.49],
    ['P-256 ECDSA sign', 1.28],
    ['P-256 ECDSA verify', 1.3],
    ['P-256 ECDH shared secret', 1.056],
    ['P-384 ECDSA verify', 1.5]
  ]],
  ['RSA, PKCS #1 v1.5', 'docs/crypto/public-key.md, Apple M4, commit 05d1481', [
    ['RSA-2048 sign', 1.11],
    ['RSA-2048 verify', 1.17],
    ['RSA-2048 OAEP decrypt', 1.12],
    ['RSA-3072 sign', 1.092],
    ['RSA-3072 verify', 1.2],
    ['RSA-4096 sign', 1.087],
    ['RSA-4096 verify', 1.21]
  ]],
  ['Certificates', 'docs/certificates.md, Apple M4, commit 05d1481', [
    ['Read 256 certificates', 6.21],
    ['Read 256, keys decoded', 5.27],
    ['Verify a chain, ECDSA leaf', 1.34],
    ['Verify a chain, RSA leaf', 1.17]
  ]]
].freeze

def ratio_words(ratio)
  ratio.positive? ? "#{ratio}× as fast" : "#{-ratio}× slower"
end

def speed_chart(palette)
  width = 1280
  row_height = 38
  group_gap = 54
  top = 190
  rows = SPEED_GROUPS.map { |group| group[2].size }.inject(:+)
  height = top + SPEED_GROUPS.size * group_gap + rows * row_height + 70
  center = 820.0
  half = 380.0
  limit = 8.0
  scale = lambda { |ratio| center + (ratio.positive? ? 1 : -1) * Math.log(ratio.abs) / Math.log(limit) * half }
  body = chart_frame(palette, width, height, 'Beryl against OpenSSL: public keys and certificates',
                     ['Operations per second, Beryl against libcrypto, median of ten rounds of 2 s per arm. Bars to the right',
                      'are faster than OpenSSL, bars to the left slower (log scale). Every row is from the docs named below.'])
  axis_bottom = height - 60
  [-4, -2, 2, 4].each do |tick|
    tick_x = scale.call(tick.to_f).round(1)
    body << %(<line x1="#{tick_x}" x2="#{tick_x}" y1="#{top - 10}" y2="#{axis_bottom}" stroke="#{palette[:grid]}" stroke-width="1"/>)
    body << text_at('Manrope-600', 14.5, 0, tick.positive? ? "#{tick}× as fast" : "#{-tick}× slower", left: tick_x, baseline: axis_bottom + 22, fill: palette[:faint], anchor: :middle)
  end
  body << %(<line x1="#{center}" x2="#{center}" y1="#{top - 10}" y2="#{axis_bottom}" stroke="#{palette[:faint]}" stroke-width="1.5" stroke-dasharray="4 4"/>)
  body << text_at('Manrope-600', 14.5, 0, 'OpenSSL', left: center, baseline: axis_bottom + 22, fill: palette[:faint], anchor: :middle)
  cursor = top
  SPEED_GROUPS.each do |group, source, list_of_rows|
    body << text_at('Manrope-800', 13.5, 0.13, group.upcase, left: 49, baseline: cursor + 22, fill: palette[:accent])
    body << text_at('Manrope-400', 14.5, 0, source, left: 49 + text_width('Manrope-800', 13.5, 0.13, group.upcase) + 14, baseline: cursor + 22, fill: palette[:faint])
    cursor += group_gap - 12
    list_of_rows.each do |label, ratio|
      bar_top = cursor + 6
      bar_end = scale.call(ratio)
      color = ratio.positive? ? palette[:series] : palette[:series2]
      body << text_at('Manrope-600', 17, 0, label, left: 49, baseline: cursor + 25, fill: palette[:text])
      x = [center, bar_end].min
      body << %(<rect x="#{x.round(1)}" y="#{bar_top}" width="#{[(bar_end - center).abs, 3].max.round(1)}" height="26" rx="5" fill="#{color}"/>)
      words = ratio_words(ratio)
      if ratio.positive?
        body << text_at('Manrope-700', 15.5, 0, words, left: [bar_end, center + 3].max + 10, baseline: cursor + 24, fill: palette[:text])
      else
        body << text_at('Manrope-700', 15.5, 0, words, left: [bar_end, center - 3].min - 10, baseline: cursor + 24, fill: palette[:text], anchor: :end)
      end
      cursor += row_height
    end
    cursor += 12
  end
  description = SPEED_GROUPS.map { |group, _, list| "#{group}: " + list.map { |label, ratio| "#{label} #{ratio_words(ratio)}" }.join(', ') }.join('. ')
  svg_open(width, height, 'Beryl against OpenSSL: public keys and certificates', "Median of ten rounds on an Apple M4. #{description}.") +
    body.join("\n") + '</svg>'
end

# ---------------------------------------------------------------- verification panel
def verified_panel(palette)
  width = 1280
  height = 330
  body = chart_frame(palette, width, height, 'How Beryl is checked',
                     ['Published vectors, Wycheproof, a differential against OpenSSL and three constant-time checks. Every pull request must pass them.'])
  stats = [
    ['9,795', 'x509-limbo cases run', 'every one matches its', palette[:accent], 'expected result'],
    ['0', 'mismatches against OpenSSL', '1,000,000 X25519 cases; 200,000 per', palette[:text], 'P-256, P-384 and Ed25519 check'],
    ['|t| < 4.5', 'dudect timing statistic', '1,000,000 measurements per class', palette[:accent], 'for the curves, on the build Mac'],
    ['0', 'findings in 10,000,000', 'mutated DER inputs fuzzed through', palette[:text], 'every certificate reader']
  ]
  column = (width - 96) / 4.0
  stats.each_with_index do |(big, label, detail, color, detail2), index|
    left = 49 + index * column
    body << %(<rect x="#{left.round(1)}" y="140" width="4" height="146" rx="2" fill="#{color}"/>)
    body << text_at('Fraunces-700', 50, -0.01, big, left: left + 22, baseline: 190, fill: color)
    body << text_at('Manrope-700', 18, 0, label, left: left + 22, baseline: 222, fill: palette[:text])
    body << text_at('Manrope-400', 15, 0, detail, left: left + 22, baseline: 248, fill: palette[:muted])
    body << text_at('Manrope-400', 15, 0, detail2.strip, left: left + 22, baseline: 270, fill: palette[:muted]) if detail2
  end
  svg_open(width, height, 'How Beryl is checked',
           'x509-limbo: 9,795 cases run, every one matches its expected result. Differential against OpenSSL: 0 mismatches over 1,000,000 X25519 cases and 200,000 cases each for P-256, P-384 and Ed25519. Timing: the dudect statistic stays below 4.5 over 1,000,000 measurements per class for the curve operations on the build Mac. Fuzzing: 0 findings in 10,000,000 mutated DER inputs run through every certificate reader.') +
    body.join("\n") + '</svg>'
end

# ---------------------------------------------------------------- Amber lockup
# The site navigation lockup: Amber's character mark beside "Amber Framework" in Fraunces.
def amber_lockup(palette)
  mark = File.join(ART, 'amber-mark.png')
  height = 72
  mark_height = 64
  mark_width = image_width(mark, mark_height)
  words_left = mark_width + 14
  words_width = text_width('Fraunces-730', 30, -0.005, 'Amber Framework')
  width = (words_left + words_width + 4).ceil
  svg_open(width, height, 'Amber Framework', 'The Amber framework logo: Amber, the framework lead, as a chibi character mark beside the words Amber Framework.') +
    image_at(mark, left: 0, top: 4, height: mark_height) +
    text_at('Fraunces-730', 30, -0.005, 'Amber Framework', left: words_left, baseline: 47, fill: palette[:text]) + '</svg>'
end

{ 'light' => LIGHT, 'dark' => DARK }.each do |name, palette|
  {
    'amber-lockup' => -> { amber_lockup(palette) },
    'badges' => -> { badges(palette) },
    'public-key-speed' => -> { speed_chart(palette) },
    'verified' => -> { verified_panel(palette) }
  }.each do |chart, draw|
    next unless LIST_OF_CHARTS.empty? || LIST_OF_CHARTS.include?(chart)

    File.write(File.join(OUT, "#{chart}-#{name}.svg"), draw.call)
  end
end
puts Dir[File.join(OUT, '*.svg')].sort.map { |path| "#{File.basename(path)} #{File.size(path)}" }
