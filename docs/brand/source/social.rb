#!/usr/bin/ruby
# Builds docs/brand/source/social.svg, the 1280x640 link preview card.
# Usage: social.rb <art-dir> <out.svg>
require_relative 'beryl_kit'
include BerylKit

ART = ARGV[0] or abort 'usage: social.rb <art-dir> <out.svg>'
OUT = ARGV[1] or abort 'usage: social.rb <art-dir> <out.svg>'
portrait = data_uri(File.join(ART, 'portrait.jpg'))
mark = File.join(ART, 'beryl-mark.png')
palette = LIGHT
left = 700

chips = ['Hashes', 'AEADs', 'Curves', 'RSA', 'X.509']
chip_parts = []
cursor = left
chips.each do |label|
  width = text_width('Manrope-700', 17, 0.04, label) + 30
  chip_parts << %(<rect x="#{cursor}" y="420" width="#{width.round(1)}" height="40" rx="20" fill="#{palette[:panel]}" stroke="#{palette[:panel_edge]}" stroke-width="1.5"/>)
  chip_parts << text_at('Manrope-700', 17, 0.04, label, left: cursor + width / 2.0, baseline: 446, fill: palette[:accent], anchor: :middle)
  cursor += width + 12
end

mark_height = 118
mark_width = image_width(mark, mark_height)
svg = svg_open(1280, 640, 'Beryl: cryptography in pure Crystal for the Amber framework',
               'Beryl, the Amber crew\'s security member, in her gold-visored helmet with her black cat Mo on her shoulder, beside her character mark and the words Beryl, cryptography in pure Crystal, no OpenSSL linked.') + <<~SVG
  <defs>
    <linearGradient id="fade" x1="0" x2="1" y1="0" y2="0">
      <stop offset=".72" stop-color="#{palette[:ground]}" stop-opacity="0"/>
      <stop offset="1" stop-color="#{palette[:ground]}" stop-opacity="1"/>
    </linearGradient>
  </defs>
  <rect width="1280" height="640" fill="#{palette[:ground]}"/>
  <image x="0" y="0" width="640" height="640" href="#{portrait}"/>
  <rect x="0" width="640" height="640" fill="url(#fade)"/>
  #{text_at('Manrope-800', 18, 0.13, 'AMBER FRAMEWORK', left: left + 2, baseline: 112, fill: palette[:accent])}
  #{image_at(mark, left: left - 6, top: 132, height: mark_height)}
  #{text_at('Fraunces-700', 104, -0.01, 'Beryl', left: left + mark_width + 4, baseline: 232, fill: palette[:text])}
  #{text_at('Fraunces-600', 38, -0.005, 'Cryptography in pure Crystal.', left: left, baseline: 312, fill: palette[:text])}
  #{text_at('Fraunces-600', 38, -0.005, 'No OpenSSL linked.', left: left, baseline: 362, fill: palette[:text])}
  #{chip_parts.join("\n")}
  #{text_at('Manrope-500', 21, 0, 'Differential against OpenSSL. Constant-time checks.', left: left + 2, baseline: 520, fill: palette[:muted])}
  #{text_at('Manrope-600', 18, 0, 'github.com/amberframework/beryl', left: left + 2, baseline: 576, fill: palette[:muted])}
</svg>
SVG

File.write(OUT, svg)
puts "#{OUT}: #{File.size(OUT)} bytes"
