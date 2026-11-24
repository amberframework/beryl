#!/usr/bin/ruby
# Builds docs/brand/hero-light.svg and hero-dark.svg: Beryl's animated README banner.
# Usage: hero.rb <art-dir> <out-dir>
require 'digest'
require_relative 'beryl_kit'
include BerylKit

ART = ARGV[0] or abort 'usage: hero.rb <art-dir> <out-dir>'
OUT = ARGV[1] or abort 'usage: hero.rb <art-dir> <out-dir>'
photo = data_uri(File.join(ART, 'scene.jpg'))
mark = File.join(ART, 'beryl-mark.png')

left = 640
strip_top = 318
strip_height = 62
strip_width = 600
strip_mid = strip_top + strip_height / 2.0

# The live element: the SHA-256 digest of a short message, revealed by a sweep.
# The digest is computed here, so the art shows the real value.
message = '"hello, Amber"'
digest = Digest::SHA256.hexdigest('hello, Amber')
code_face = 'Manrope-600'
code_size = 16.5

chip_left = left + 14
chip_label = 'SHA-256'
chip_width = text_width('Manrope-800', 14, 0.06, chip_label) + 24
text_left = chip_left + chip_width + 18
room = left + strip_width - 18 - text_left
shown = digest.dup
shown = shown[0..-2] while text_width(code_face, code_size, 0, "#{shown}…") > room
shown = "#{shown}…"
digest_width = text_width(code_face, code_size, 0, shown)

# Timeline (percent of a 9 s loop): the sweep crosses the digest from 10% to 58%.
sweep_from = text_left - 8
sweep_to = text_left + digest_width + 8
reveal_width = (sweep_to - sweep_from).round(1)

THEMES = {
  'dark' => {
    ground: '#241A15', strip: '#171311', strip_alpha: '1', text: '#FFF7ED', muted: '#CDBEB4', faint: '#AA9A90',
    accent: '#FFBD74', sweep: '#FFC777', edge: '#4B3B32'
  },
  'light' => {
    ground: '#FFF9EF', strip: '#FFFDF9', strip_alpha: '1', text: '#211914', muted: '#453930', faint: '#76675D',
    accent: '#A93D08', sweep: '#D95B0A', edge: '#D9AD7E'
  }
}.freeze

THEMES.each do |name, theme|
  ground = theme[:ground]
  mark_height = 84
  mark_width = image_width(mark, mark_height)
  word_left = left + mark_width + 6
  svg = <<~SVG
    <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 1280 440" width="1280" height="440" role="img" aria-labelledby="title desc">
      <title id="title">Beryl: cryptography in pure Crystal, with no OpenSSL linked. Security for the Amber framework.</title>
      <desc id="desc">Beryl, the Amber crew's security member, in her gold-visored helmet beside her motorcycle on a rooftop at sunset, her black cat Mo on her shoulder. Beside her, Beryl's character mark and name, and a strip where a sweep passes over the message "hello, Amber" and leaves its SHA-256 digest, #{digest[0, 16]}..., behind it.</desc>
      <style>
        .sweep { animation: sweep 9s linear infinite; }
        .plain { animation: plain 9s linear infinite; transform-box: fill-box; transform-origin: left center; transform: scaleX(0); }
        .cover { animation: cover 9s linear infinite; transform-box: fill-box; transform-origin: right center; }
        .result { animation: result 9s ease-out infinite; opacity: 0; }
        @keyframes sweep {
          0%, 10% { transform: translate(#{sweep_from}px, 0); opacity: 0; }
          12% { opacity: 1; }
          58% { transform: translate(#{sweep_to}px, 0); opacity: 1; }
          62%, 100% { transform: translate(#{sweep_to}px, 0); opacity: 0; }
        }
        @keyframes plain { 0%, 10% { transform: scaleX(0); } 58%, 92% { transform: scaleX(1); } 96%, 100% { transform: scaleX(0); } }
        @keyframes cover { 0%, 10% { transform: scaleX(1); } 58%, 92% { transform: scaleX(0); } 96%, 100% { transform: scaleX(1); } }
        @keyframes result { 0%, 60% { opacity: 0; } 66%, 90% { opacity: 1; } 96%, 100% { opacity: 0; } }
        @media (prefers-reduced-motion: reduce) {
          .sweep { animation: none; opacity: 0; }
          .plain { animation: none; transform: scaleX(1); }
          .cover { animation: none; transform: scaleX(0); }
          .result { animation: none; opacity: 1; }
        }
      </style>
      <defs>
        <clipPath id="card"><rect width="1280" height="440" rx="22"/></clipPath>
        <clipPath id="before"><rect class="cover" x="#{sweep_from}" y="#{strip_mid - 18}" width="#{reveal_width}" height="36"/></clipPath>
        <clipPath id="after"><rect class="plain" x="#{sweep_from}" y="#{strip_mid - 18}" width="#{reveal_width}" height="36"/></clipPath>
        <linearGradient id="shade" x1="0" x2="1" y1="0" y2="0">
          <stop offset=".30" stop-color="#{ground}" stop-opacity="0"/>
          <stop offset=".47" stop-color="#{ground}" stop-opacity=".86"/>
          <stop offset=".57" stop-color="#{ground}" stop-opacity="1"/>
          <stop offset="1" stop-color="#{ground}" stop-opacity="1"/>
        </linearGradient>
        <linearGradient id="beam" x1="0" x2="1" y1="0" y2="0">
          <stop offset="0" stop-color="#{theme[:sweep]}" stop-opacity="0"/>
          <stop offset=".85" stop-color="#{theme[:sweep]}" stop-opacity=".35"/>
          <stop offset="1" stop-color="#{theme[:sweep]}" stop-opacity="1"/>
        </linearGradient>
      </defs>

      <g clip-path="url(#card)">
        <rect width="1280" height="440" fill="#{ground}"/>
        <image x="-40" y="-14" width="1002" height="564" preserveAspectRatio="xMidYMid slice" href="#{photo}"/>
        <rect width="1280" height="440" fill="url(#shade)"/>

        #{text_at('Manrope-800', 13.5, 0.13, 'AMBER FRAMEWORK  ·  SECURITY', left: left + 2, baseline: 56, fill: theme[:accent])}
        #{image_at(mark, left: left - 4, top: 64, height: mark_height)}
        #{text_at('Fraunces-700', 70, -0.01, 'Beryl', left: word_left, baseline: 136, fill: theme[:text])}
        #{text_at('Fraunces-600', 36, -0.005, 'Cryptography in pure Crystal.', left: left, baseline: 192, fill: theme[:text])}
        #{text_at('Fraunces-600', 36, -0.005, 'No OpenSSL linked.', left: left, baseline: 236, fill: theme[:text])}
        #{text_at('Manrope-500', 17.5, 0, 'Hashes, AEADs, Ed25519, X25519, P-256, P-384, RSA and X.509.', left: left + 1, baseline: 274, fill: theme[:muted])}
        #{text_at('Manrope-500', 17.5, 0, 'Checked against OpenSSL and for constant time on every PR.', left: left + 1, baseline: 298, fill: theme[:muted])}

        <!-- the live digest -->
        <rect x="#{left}" y="#{strip_top}" width="#{strip_width}" height="#{strip_height}" rx="14" fill="#{theme[:strip]}" stroke="#{theme[:edge]}" stroke-width="1.2"/>
        <rect x="#{chip_left}" y="#{strip_mid - 16}" width="#{chip_width.round(1)}" height="32" rx="8" fill="#{theme[:accent]}" fill-opacity=".12" stroke="#{theme[:accent]}" stroke-opacity=".6"/>
        #{text_at('Manrope-800', 14, 0.06, chip_label, left: chip_left + 12, baseline: strip_mid + 5, fill: theme[:accent])}
        <g clip-path="url(#before)">#{text_at(code_face, code_size, 0, message, left: text_left, baseline: strip_mid + 6, fill: theme[:text])}</g>
        <g clip-path="url(#after)">#{text_at(code_face, code_size, 0, shown, left: text_left, baseline: strip_mid + 6, fill: theme[:accent])}</g>
        <g class="sweep"><rect x="-46" y="#{strip_mid - 20}" width="46" height="40" fill="url(#beam)"/><rect x="-1.5" y="#{strip_mid - 22}" width="3" height="44" rx="1.5" fill="#{theme[:sweep]}"/></g>

        #{text_at('Manrope-800', 12.5, 0.13, 'NO LIBSSL  ·  NO LIBCRYPTO', left: left + 2, baseline: 410, fill: theme[:faint])}
        #{text_at('Manrope-800', 12.5, 0.13, 'SAME DIGEST AS OPENSSL', left: left + strip_width - 2, baseline: 410, fill: theme[:accent], anchor: :end, extra: ' class="result"')}
      </g>
      <rect x=".75" y=".75" width="1278.5" height="438.5" rx="21.5" fill="none" stroke="#{theme[:edge]}" stroke-width="1.5"/>
    </svg>
  SVG
  path = File.join(OUT, "hero-#{name}.svg")
  File.write(path, svg)
  puts "#{path}: #{File.size(path)} bytes; digest shown #{shown}"
end
