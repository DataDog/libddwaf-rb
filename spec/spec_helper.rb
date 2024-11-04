require 'pry'

RSpec.configure do |config|
  config.default_formatter = 'doc'
end

# Class to make all threads wait for each other
class Barrier
  def initialize(count)
    @mutex = Mutex.new
    @cond = ConditionVariable.new
    @count = count
  end

  def sync
    @mutex.synchronize do
      @count -= 1
      if @count.positive?
        @cond.wait @mutex
      else
        @cond.broadcast
      end
    end
  end
end
