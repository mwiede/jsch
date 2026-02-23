#!/usr/bin/env python

import asyncio
import asyncssh
import sys


class MySFTPServer(asyncssh.SFTPServer):
    def __init__(self, chan):
        root = '/'
        super().__init__(chan, chroot=root)


async def start_server():
    await asyncssh.listen(
        '',
        22,
        sftp_factory=MySFTPServer,
        allow_scp=True,
        authorized_client_keys='/root/.ssh/authorized_keys',
        server_host_keys=['/etc/ssh/ssh_host_ed448_key'],
        server_host_certs=['/etc/ssh/ssh_host_ed448_key-cert.pub'],
        signature_algs=['ssh-ed448'],
    )


async def run():
    await start_server()
    await asyncio.get_event_loop().create_future()  # run forever


try:
    asyncio.run(run())
except (ValueError, OSError, asyncssh.Error) as exc:
    sys.exit('Error starting server: ' + str(exc))