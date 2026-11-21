"""Client side of the NAT new-connection-rate check.

`open` offers new TCP connections through the masquerade at a fixed rate
(open loop: a slow firewall cannot slow the offer down, it can only make
connections time out) and reports what completed. `hold` keeps long-lived
connections open and echoing until told to stop. Every number printed is
measured on the wire peer's answers; nothing reads or repairs product state.
"""
import argparse
import asyncio
import json
import multiprocessing
import resource
import socket
import sys
import time
from pathlib import Path

BACKEND = '198.18.10.254'
SHORT_PORT = 9200
HELD_PORT = 9201
WAN_IP = '198.18.10.100'


def raise_fd_limit():
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    wanted = 65536 if hard == resource.RLIM_INFINITY else min(hard, 65536)
    if soft < wanted:
        resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(fraction * len(ordered)))]


async def one_connection(start_at, timeout, loop):
    delay = start_at - loop.time()
    if delay > 0:
        await asyncio.sleep(delay)
    lag = loop.time() - start_at
    began = time.monotonic()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(BACKEND, SHORT_PORT), timeout)
        connected = time.monotonic()
        writer.write(b'cps\n')
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout)
        if not line:
            return {'kind': 'closed-without-answer', 'lag': lag}
        peer = json.loads(line)['peer']
        if peer[0] != WAN_IP:
            return {'kind': 'untranslated', 'lag': lag, 'peer': peer}
        return {'kind': 'ok', 'lag': lag, 'connect': connected - began,
                'total': time.monotonic() - began, 'wan_port': peer[1]}
    except asyncio.TimeoutError:
        return {'kind': 'timeout', 'lag': lag}
    except (OSError, ValueError, KeyError) as error:
        return {'kind': type(error).__name__, 'lag': lag}
    finally:
        if writer is not None:
            writer.close()


async def offer(count, rate, timeout):
    loop = asyncio.get_running_loop()
    first = loop.time() + 0.2
    tasks = [asyncio.create_task(one_connection(first + index / rate, timeout, loop))
             for index in range(count)]
    return await asyncio.gather(*tasks)


def open_worker(job):
    count, rate, timeout = job
    raise_fd_limit()
    began = time.monotonic()
    rows = asyncio.run(offer(count, rate, timeout))
    return {'rows': rows, 'wall': time.monotonic() - began}


def open_phase(args):
    per_worker = args.count // args.processes
    jobs = [(per_worker, args.rate / args.processes, args.timeout)] * args.processes
    began = time.monotonic()
    with multiprocessing.Pool(args.processes) as pool:
        results = pool.map(open_worker, jobs)
    wall = time.monotonic() - began
    rows = [row for result in results for row in result['rows']]
    ok = [row for row in rows if row['kind'] == 'ok']
    kinds = {}
    for row in rows:
        kinds[row['kind']] = kinds.get(row['kind'], 0) + 1
    offered_for = per_worker / (args.rate / args.processes)
    connect = [row['connect'] for row in ok]
    lags = [row['lag'] for row in rows]
    print(json.dumps({
        'offered': len(rows),
        'offered_rate': args.rate,
        'offered_for_s': round(offered_for, 3),
        'completed': len(ok),
        'failures': {kind: n for kind, n in kinds.items() if kind != 'ok'},
        'completed_rate': round(len(ok) / max(offered_for, 1e-9), 1),
        'wall_s': round(wall, 3),
        'connect_p50_ms': round(1000 * percentile(connect, 0.50), 2) if connect else None,
        'connect_p99_ms': round(1000 * percentile(connect, 0.99), 2) if connect else None,
        'connect_max_ms': round(1000 * max(connect), 2) if connect else None,
        'retransmit_shaped_connects': sum(1 for value in connect if value >= 0.9),
        'client_lag_p99_ms': round(1000 * percentile(lags, 0.99), 2),
        'distinct_wan_ports': len({row['wan_port'] for row in ok}),
    }))


def hold_phase(args):
    raise_fd_limit()
    held = []
    for index in range(args.count):
        connection = socket.create_connection((BACKEND, HELD_PORT), timeout=10)
        stream = connection.makefile('rwb', buffering=0)
        peer = json.loads(stream.readline(4096))['peer']
        assert peer[0] == WAN_IP, peer
        held.append({'index': index, 'socket': connection, 'stream': stream,
                     'wan_port': peer[1], 'local_port': connection.getsockname()[1]})
    ports = [row['wan_port'] for row in held]
    assert len(set(ports)) == len(ports), 'two held connections share a WAN port'
    Path(args.ready).write_text(json.dumps(ports))
    rounds = 0
    failures = []
    release = Path(args.release)
    while True:
        last = release.exists()
        for row in held:
            frame = f'held:{rounds}:{row["index"]}\n'.encode()
            try:
                row['stream'].write(frame)
                answer = row['stream'].readline(4096)
            except OSError as error:
                answer = repr(error).encode()
            if answer != frame:
                failures.append({'round': rounds, 'index': row['index'],
                                 'answer': answer.decode(errors='replace')[:80]})
        rounds += 1
        if last:
            break
        time.sleep(args.interval)
    for row in held:
        row['socket'].close()
    Path(args.out).write_text(json.dumps({'held': len(held), 'rounds': rounds,
                                          'echo_failures': failures,
                                          'wan_ports': ports}))


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='action', required=True)
    opened = sub.add_parser('open')
    opened.add_argument('--count', type=int, required=True)
    opened.add_argument('--rate', type=float, required=True)
    opened.add_argument('--processes', type=int, default=4)
    opened.add_argument('--timeout', type=float, default=5.0)
    hold = sub.add_parser('hold')
    hold.add_argument('--count', type=int, required=True)
    hold.add_argument('--interval', type=float, default=2.0)
    hold.add_argument('--ready', required=True)
    hold.add_argument('--release', required=True)
    hold.add_argument('--out', required=True)
    args = parser.parse_args()
    if args.action == 'open':
        open_phase(args)
    else:
        hold_phase(args)


if __name__ == '__main__':
    sys.exit(main())
