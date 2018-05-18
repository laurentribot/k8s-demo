FROM alpine:3.7

COPY script.sh kubectl /bin/
RUN chmod u+x /bin/script.sh /bin/kubectl
ENTRYPOINT /bin/script.sh
