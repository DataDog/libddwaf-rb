ARG RUBY_VERSION

FROM ruby:${RUBY_VERSION:-2.5}

# EOL Debian buster: no fixed ca-certificates package ships, so drop the two compromised roots from the bundle.
RUN sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' /etc/ca-certificates.conf \
 && rm -f /usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt /usr/share/ca-certificates/mozilla/Comodo_AAA_Services_root.crt \
 && update-ca-certificates -f

RUN gem update --system 3.3.27
