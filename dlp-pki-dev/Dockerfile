FROM my-docker-registry:5443/python:2.7.15-slim

WORKDIR /usr/src/app

COPY dist/dlp-pki-dev-1.0.tar.gz dlp-pki-dev.tar.gz
RUN pip install --quiet --index-url http://192.168.56.10:9090 --disable-pip-version-check --trusted-host 192.168.56.10 --no-cache-dir dlp-pki-dev.tar.gz

EXPOSE 8080
VOLUME [ "/etc/dlppkidev" ]

ENTRYPOINT [ "/usr/local/bin/dlp-pki-dev" ]
CMD [ "--config=/etc/dlppkidev/dlppkidev.yml" ]
