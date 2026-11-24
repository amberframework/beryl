# Shared drawing helpers for Beryl's README art, in the Amber framework's brand
# (amberframework.org, app/assets/css/amber-brand.css): Amber's two typefaces,
# Fraunces for display and Manrope for everything else, drawn as vector outlines,
# and the site's own light and dark palettes. The same kit drew Mica's art
# (amberframework/mica, docs/brand/source).
#
# Fonts (not committed; put them in ../fonts beside this folder, check each sha256):
#   Fraunces-Variable.woff2  e169df7559440091b2d3499a0d40f9f34baa6114bf4ce709fe53f329beeecb4a
#   Manrope-Variable.woff2   52ecbc78831e7ae0431b4a5cbe4aaaae27255c9d370659b0b0bb9bd2f19ec42b
#     both from amberframework/amberframework.org, app/assets/fonts/ (SIL OFL)
#
# Art (not committed; the built SVGs embed it). Beryl's art is from the Amberverse
# canon (amberverse-roadmap-3d, branch character/beryl, research/beryl_concepts/codex/selected/):
#   scene.jpg        beryl-rooftop-motorcycle-scene.png resized to 1400 px wide,
#                    sha256 2ae642ba7d9be4c8e49a93774a0997e96d55e9743937ed255e62c361d15ffc47
#   portrait.jpg     beryl-id-original-studio.png resized to 640 px,
#                    sha256 abd056da57074f8dd99693ee62e55031ea92617c871372909cb182856a4e9ab5
#   beryl-mark.png   beryl-chibi-hero-mark.png, trimmed, 240 px tall,
#                    sha256 849c44fe491041ecacd7b1469e503f3dc48c0b8eb1597935ba322bdadfbcf1a2
#   amber-mark.png   Amber's primary character mark, trimmed, 200 px tall (amberframework.org
#                    app/assets/characters/amber-chibi-hero-mark-v2.webp,
#                    sha256 16048f5601f3c5688e54824f1cf9007a9417145f78f1af6135e43008d4611dd8)
# Prepare:  magick <scene.png> -resize 1400x -quality 84 scene.jpg
#           magick <portrait.png> -resize 640x640 -quality 86 portrait.jpg
#           magick <mark.png> -trim +repage -resize x240 beryl-mark.png   (x200 for amber-mark.png)
# Build: swiftc -O textpath.swift -o textpath; then
#   /usr/bin/ruby hero.rb <art-dir> ..
#   /usr/bin/ruby assets.rb <art-dir> ..
#   /usr/bin/ruby social.rb <art-dir> social.svg   (render to ../social-preview.png at 1280x640)
require 'base64'

module BerylKit
  FONTS = File.join(__dir__, '..', 'fonts')
  TEXTPATH = File.join(__dir__, 'textpath')

  FACES = {
    'Fraunces-600' => ['Fraunces-Variable.woff2', 600],
    'Fraunces-700' => ['Fraunces-Variable.woff2', 700],
    'Fraunces-730' => ['Fraunces-Variable.woff2', 730],
    'Manrope-400' => ['Manrope-Variable.woff2', 400],
    'Manrope-500' => ['Manrope-Variable.woff2', 500],
    'Manrope-600' => ['Manrope-Variable.woff2', 600],
    'Manrope-700' => ['Manrope-Variable.woff2', 700],
    'Manrope-800' => ['Manrope-Variable.woff2', 800]
  }.freeze

  # Light: the site's canvas, paper, ink and amber scale.
  # Dark: the site's footer, dark sections and terminal window.
  LIGHT = {
    ground: '#FFF9EF', panel: '#FFFDF9', panel_edge: '#D9AD7E', grid: '#E9D3B9',
    text: '#211914', muted: '#76675D', faint: '#76675D',
    accent: '#A93D08',                   # amber-700: small text and labels
    series: '#F47A16', on_series: '#211914',   # amber-500 bars, ink labels
    series2: '#A93D08', on_series2: '#FFFDF9', # amber-700 bars, paper labels
    third: '#453930',                    # ink-soft
    bar_track: '#FFF0D7', loupe: '#D95B0A'
  }.freeze
  DARK = {
    ground: '#241A15', panel: '#241A15', panel_edge: '#4B3B32', grid: '#3D302A',
    text: '#FFF7ED', muted: '#CDBEB4', faint: '#AA9A90',
    accent: '#FFBD74',
    series: '#F47A16', on_series: '#211914',
    series2: '#FFC777', on_series2: '#211914', # amber-300 bars, ink labels
    third: '#FFF7ED',
    bar_track: '#30221C', loupe: '#FFC777'
  }.freeze

  module_function

  def text_shape(face, size, tracking, words)
    file, weight = FACES.fetch(face)
    env = weight ? { 'WGHT' => weight.to_s } : {}
    output = IO.popen(env, [TEXTPATH, File.join(FONTS, file), size.to_s, tracking.to_s, words], &:read)
    width, path_data = output.strip.split("\t", 2)
    [width.to_f, path_data.to_s]
  end

  def text_width(face, size, tracking, words)
    text_shape(face, size, tracking, words).first
  end

  def text_at(face, size, tracking, words, left:, baseline:, fill:, anchor: :start, extra: '')
    width, path_data = text_shape(face, size, tracking, words)
    left -= width / 2 if anchor == :middle
    left -= width if anchor == :end
    %(<path transform="translate(#{left.round(2)} #{baseline})" fill="#{fill}" d="#{path_data}"#{extra}/>)
  end

  def escape(text)
    text.gsub('&', '&amp;').gsub('<', '&lt;').gsub('>', '&gt;')
  end

  def svg_open(width, height, title, description)
    %(<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 #{width} #{height}" width="#{width}" height="#{height}" role="img" aria-labelledby="t d">) +
      %(<title id="t">#{escape(title)}</title><desc id="d">#{escape(description)}</desc>)
  end

  def data_uri(path)
    type = path.end_with?('.png') ? 'image/png' : 'image/jpeg'
    "data:#{type};base64,#{Base64.strict_encode64(File.binread(path))}"
  end

  # A raster from the art folder, placed by its top-left corner and height.
  def image_at(path, left:, top:, height:, extra: '')
    pixel_width, pixel_height = File.binread(path, 24)[16, 8].unpack('NN') if path.end_with?('.png')
    width = pixel_width ? (height * pixel_width.to_f / pixel_height).round(1) : height
    uri = data_uri(path)
    %(<image x="#{left}" y="#{top}" width="#{width}" height="#{height}" href="#{uri}"#{extra}/>)
  end

  def image_width(path, height)
    pixel_width, pixel_height = File.binread(path, 24)[16, 8].unpack('NN')
    (height * pixel_width.to_f / pixel_height).round(1)
  end
end
