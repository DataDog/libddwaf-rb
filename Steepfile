# D = Steep::Diagnostic

target :lib do
  signature "sig"

  check "lib"
  library "logger"
  library "monitor" # needed by logger
  library "json"

  repo_path "vendor/rbs"
  library "ffi"
  library "jruby"
  library "gem"

#   # configure_code_diagnostics(D::Ruby.strict)       # `strict` diagnostics setting
#   # configure_code_diagnostics(D::Ruby.lenient)      # `lenient` diagnostics setting
#   # configure_code_diagnostics do |hash|             # You can setup everything yourself
#   #   hash[D::Ruby::NoMethod] = :information
#   # end
end
