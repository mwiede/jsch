FROM alpine:3.16
RUN apk add --update openssh openssh-server bash && rm /var/cache/apk/*
RUN adduser -D luigi
RUN echo 'luigi:passwordLuigi' | chpasswd
RUN mkdir -p /home/luigi/.ssh
COPY ["sshd_config","/etc/ssh/sshd_config"]
COPY ["authorized_keys","/home/luigi/.ssh/authorized_keys"]
COPY ["entrypoint.sh","/entrypoint.sh"]
COPY ["ssh_host_rsa_key","/etc/ssh/ssh_host_rsa_key"]
COPY ["ssh_host_rsa_key-cert.pub","/etc/ssh/ssh_host_rsa_key-cert.pub"]
COPY ["ssh_host_ecdsa_key","/etc/ssh/ssh_host_ecdsa_key"]
COPY ["ssh_host_ecdsa_key-cert.pub","/etc/ssh/ssh_host_ecdsa_key-cert.pub"]
COPY ["ssh_host_ed25519_key","/etc/ssh/ssh_host_ed25519_key"]
COPY ["ssh_host_ed25519_key-cert.pub","/etc/ssh/ssh_host_ed25519_key-cert.pub"]
ENTRYPOINT /entrypoint.sh