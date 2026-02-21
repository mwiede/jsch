#!/bin/bash
chown -R luigi /home/luigi
chmod 0600 /home/luigi/.ssh/*
chmod 600 /etc/ssh/ssh_*_key -R
/usr/sbin/sshd -D -ddd -e
