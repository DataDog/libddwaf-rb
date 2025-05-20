FROM ruby:3.4

RUN apt-get update && apt-get install -y valgrind --no-install-recommends --no-install-suggests

ADD . /libddwaf-rb

WORKDIR /libddwaf-rb

RUN bundle install

CMD /bin/bash
