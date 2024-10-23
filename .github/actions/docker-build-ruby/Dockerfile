ARG RUBY_VERSION

FROM ruby:${RUBY_VERSION:-2.5}

RUN git config --global --add safe.directory '/libddwaf-rb'

RUN gem update --system 3.3.27
