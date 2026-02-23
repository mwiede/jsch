FROM alpine:3.5
RUN apk update && \
    apk upgrade && \
    apk add openssh bash && \
    rm /var/cache/apk/* && \
    mkdir -p /root/.ssh && \
    chmod 700 /root/.ssh
COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
COPY ca_jsch_key.pub /etc/ssh/ca_jsch_key.pub
RUN chmod 644 /etc/ssh/ca_jsch_key.pub && \
    chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]