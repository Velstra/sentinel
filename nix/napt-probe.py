"""Keep 128 real translated TCP sessions open; no product map read or repair."""
import json
import socket

sockets=[]
observed=[]
try:
    for remote in (9101,10920):
        source_base=43000 if remote==9101 else 43100
        for address in ('198.18.20.50','198.18.20.51'):
            for source_port in range(source_base,source_base+32):
                connection=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                sockets.append(connection)
                connection.settimeout(5)
                try:
                    connection.bind((address,source_port))
                except OSError as error:
                    raise RuntimeError(f'client fixture bind {address}:{source_port} -> {remote}, verified sessions={len(observed)}') from error
                connection.connect(('198.18.10.254',remote))
                stream=connection.makefile('rwb',buffering=16384)
                peer=json.loads(stream.readline(4096))['peer']
                assert peer[0]=='198.18.10.100',peer
                assert 32768<=peer[1]<=65535,peer
                observed.append({'source':address,'source_port':source_port,'remote_port':remote,'wire_peer':peer,'stream':stream})
    assert len(observed)==128
    for remote in (9101,10920):
        assert len({row['wire_peer'][1] for row in observed if row['remote_port']==remote})==64
    verified_bytes=0
    for round_id in range(2):
        for index,row in enumerate(observed):
            frame=(f'sentinel-napt:{round_id}:{index}:'.encode()+b'x'*8192+b'\n')
            row['stream'].write(frame)
            row['stream'].flush()
            answer=row['stream'].readline(len(frame)+1)
            assert answer==frame,(round_id,index,len(answer))
            verified_bytes+=len(frame)
    print(json.dumps({'concurrent_connections':128,'sources':2,'backends':2,
                      'all_wire_peers_are_WAN_SNAT_IP':True,'unique_WAN_ports_per_backend':64,
                      'rounds_with_all_sessions_open':2,'verified_echo_bytes':verified_bytes,
                      'observations':[{k:v for k,v in row.items() if k!='stream'} for row in observed]}))
finally:
    for row in observed:
        row['stream'].close()
    for connection in sockets:
        connection.close()
