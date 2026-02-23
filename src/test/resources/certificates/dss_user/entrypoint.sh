#!/bin/bash
# Generate host keys (RSA and ECDSA) so sshd can start.
# We do not ship pre-generated host keys; any key type accepted by the
# client with StrictHostKeyChecking=no works fine here.
ssh-keygen -A
# Run without the -d debug flag so sshd stays up for multiple test methods.
# LogLevel DEBUG3 in sshd_config still produces verbose output via -e.
/usr/sbin/sshd -D -e