FROM fedora:41
RUN dnf -y update && \
    dnf -y install python3-pip && \
    dnf -y clean all && \
    pip install 'asyncssh[bcrypt]~=2.18.0' && \
    pip cache purge && \
    mkdir /root/.ssh && \
    chmod 700 /root/.ssh
COPY asyncsshd_cert.py /
COPY ssh_host_ed448_key /etc/ssh/
COPY ssh_host_ed448_key-cert.pub /etc/ssh/
COPY id_ecdsa_nistp521.pub /root/.ssh/authorized_keys
RUN chmod 600 /etc/ssh/ssh_host_ed448_key /root/.ssh/authorized_keys
RUN passwd -u root
ENTRYPOINT ["python", "/asyncsshd_cert.py"]