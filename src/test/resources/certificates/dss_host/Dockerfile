FROM alpine:3.5
RUN apk update && \
    apk upgrade && \
    apk add openssh bash && \
    rm /var/cache/apk/* && \
    mkdir -p /root/.ssh && \
    chmod 700 /root/.ssh
COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
COPY ssh_host_dsa_key /etc/ssh/ssh_host_dsa_key
COPY ssh_host_dsa_key-cert.pub /etc/ssh/ssh_host_dsa_key-cert.pub
COPY id_ecdsa_nistp521.pub /root/.ssh/authorized_keys
RUN chmod 600 /etc/ssh/ssh_host_dsa_key /root/.ssh/authorized_keys && \
    chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]