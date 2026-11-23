require "./encoding/error"
require "./encoding/distinguished_encoding_rules"
require "./encoding/privacy_enhanced_mail"

# The encodings Beryl reads keys and certificates in: DER (ITU-T X.690) and
# PEM (RFC 7468). Both readers are sans-IO and bounded; see
# `Beryl::Encoding::DER` and `Beryl::Encoding::PEM`.
module Beryl::Encoding
end
