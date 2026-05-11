FROM ruby:4.0

# clang is needed on aarch64-linux for the FFX-style trampolines: gcc on
# aarch64 silently ignores __attribute__((naked)) (extconf's probe rejects it),
# but clang honours it. Without clang the build falls back to plain wrappers
# (TRAMPOLINES=false) which is correct but loses ZJIT specialisation.
RUN apt-get update && \
    apt-get install -y --no-install-recommends --no-install-suggests \
      valgrind libc6-dbg cmake build-essential binutils clang

ADD . /libddwaf-rb

WORKDIR /libddwaf-rb

# Use clang so the naked-attribute probe in extconf.rb passes and the C
# extension emits FFX trampolines. extconf.rb honors $CC.
ENV CC=clang

RUN bundle install

CMD /bin/bash
