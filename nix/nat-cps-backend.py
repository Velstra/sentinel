"""QA peer on the WAN side of the NAT new-connection-rate check.

Port 9200 answers one line with the wire peer it saw and closes (the short
flows). Port 9201 reports the wire peer, then echoes lines until the client
closes (the long-lived flows). It records nothing and repairs nothing.
"""
import asyncio
import json
import multiprocessing
import os
import sys

HOST = '198.18.10.254'
SHORT_PORT = 9200
HELD_PORT = 9201
BACKLOG = 4096
LINE_LIMIT = 4096


async def short(reader, writer):
    try:
        await asyncio.wait_for(reader.readline(), 10)
        writer.write((json.dumps({'peer': writer.get_extra_info('peername')[:2]}) + '\n').encode())
        await writer.drain()
    except (asyncio.TimeoutError, OSError):
        pass
    finally:
        writer.close()


async def held(reader, writer):
    try:
        writer.write((json.dumps({'peer': writer.get_extra_info('peername')[:2]}) + '\n').encode())
        await writer.drain()
        while True:
            line = await reader.readline()
            if not line or len(line) > LINE_LIMIT:
                return
            writer.write(line)
            await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()


async def serve():
    servers = [
        await asyncio.start_server(short, HOST, SHORT_PORT, reuse_port=True, backlog=BACKLOG),
        await asyncio.start_server(held, HOST, HELD_PORT, reuse_port=True, backlog=BACKLOG),
    ]
    await asyncio.gather(*(server.serve_forever() for server in servers))


def worker(_index):
    asyncio.run(serve())


if __name__ == '__main__':
    processes = int(sys.argv[1]) if len(sys.argv) > 1 else os.cpu_count() or 1
    children = [multiprocessing.Process(target=worker, args=(i,)) for i in range(processes)]
    for child in children:
        child.start()
    for child in children:
        child.join()
    sys.exit(1)
