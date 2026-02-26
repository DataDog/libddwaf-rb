FROM ruby:4.0

RUN apt-get update && apt-get install -y valgrind libc6-dbg cmake build-essential binutils --no-install-recommends --no-install-suggests

ADD . /libddwaf-rb

WORKDIR /libddwaf-rb

RUN bundle install

CMD /bin/bash
