module Datadog
  module AppSec
    module WAF
      module VERSION
        BASE_STRING = '1.22.0'
        # NOTE: Every change to the `BASE_STRING` should be accompanied
        #       by a reset of the patch version in the `STRING` below.
        STRING = "#{BASE_STRING}.0.4"
        MINIMUM_RUBY_VERSION = '2.5'
      end
    end
  end
end
