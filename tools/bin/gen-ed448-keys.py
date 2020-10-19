#!/usr/bin/env python

import asyncssh

user_key = asyncssh.generate_private_key('ssh-ed448', 'test')
user_key.write_private_key('id_ed448')
user_key.write_public_key('id_ed448.pub')

host_key = asyncssh.generate_private_key('ssh-ed448', 'test')
host_key.write_private_key('ssh_host_ed448_key')
host_key.write_public_key('ssh_host_ed448_key.pub')
