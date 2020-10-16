#!/usr/bin/env python

import asyncio
import asyncssh
import sys


class MySFTPServer(asyncssh.SFTPServer):
    def __init__(self, chan):
        root = '/'
        super().__init__(chan, chroot=root)


async def start_server():
    await asyncssh.listen('', 22, sftp_factory=MySFTPServer, allow_scp=True,
                          authorized_client_keys='/root/.ssh/authorized_keys',
                          server_host_keys=['/etc/ssh/ssh_host_ecdsa256_key', '/etc/ssh/ssh_host_ecdsa384_key',
                                            '/etc/ssh/ssh_host_ecdsa521_key', '/etc/ssh/ssh_host_ed448_key',
                                            '/etc/ssh/ssh_host_ed25519_key', '/etc/ssh/ssh_host_rsa_key'],
                          kex_algs=['curve448-sha512', 'curve25519-sha256', 'curve25519-sha256@libssh.org',
                                    'ecdh-sha2-nistp521', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp256',
                                    'diffie-hellman-group18-sha512', 'diffie-hellman-group17-sha512',
                                    'diffie-hellman-group16-sha512', 'diffie-hellman-group15-sha512',
                                    'diffie-hellman-group14-sha256', 'diffie-hellman-group-exchange-sha256',
                                    'diffie-hellman-group-exchange-sha1', 'diffie-hellman-group14-sha1',
                                    'diffie-hellman-group1-sha1'],
                          signature_algs=['ecdsa-sha2-nistp521', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp256',
                                          'ssh-ed448', 'ssh-ed25519', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa'],
                          encryption_algs=['aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr',
                                           'aes192-ctr', 'aes128-ctr', 'aes256-cbc', 'aes192-cbc', 'aes128-cbc',
                                           '3des-cbc', 'blowfish-cbc', 'arcfour', 'arcfour256', 'arcfour128',
                                           'cast128-cbc'],
                          mac_algs=['hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com',
                                    'hmac-sha1-etm@openssh.com', 'hmac-sha2-512', 'hmac-sha2-256', 'hmac-sha1',
                                    'hmac-sha1-96-etm@openssh.com', 'hmac-sha1-96', 'hmac-md5-etm@openssh.com',
                                    'hmac-md5', 'hmac-md5-96-etm@openssh.com', 'hmac-md5-96'],
                          compression_algs=['zlib@openssh.com', 'zlib', 'none'])


loop = asyncio.get_event_loop()

try:
    loop.run_until_complete(start_server())
except (OSError, asyncssh.Error) as exc:
    sys.exit('Error starting server: ' + str(exc))

loop.run_forever()
