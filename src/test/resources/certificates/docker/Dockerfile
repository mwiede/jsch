FROM alpine:3.13
RUN apk update && \
    apk upgrade && \
    apk add openssh openssh-server bash && \
    rm /var/cache/apk/* && \
    mkdir /root/.ssh && \
    chmod 700 /root/.ssh
COPY ssh_host_rsa_key /etc/ssh/
COPY ssh_host_rsa_key.pub /etc/ssh/
COPY ssh_host_rsa_key-cert.pub /etc/ssh/ssh_host_rsa_key-cert.pub
COPY sshd_config /etc/ssh/
COPY ca_jsch_key.pub /etc/ssh/ca_jsch_key.pub

RUN chmod 600 /etc/ssh/ssh_*_key /root/.ssh -R
RUN passwd -u root
EXPOSE 22
ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e"]