#!/bin/bash
chmod 600 /etc/ssh/ssh_host_dsa_key
chmod 600 /root/.ssh/authorized_keys
# Run without -d/-ddd debug flag: that flag causes sshd to exit after one
# connection, which would break subsequent test methods sharing the container.
# LogLevel DEBUG3 in sshd_config still produces verbose output via -e.
/usr/sbin/sshd -D -e