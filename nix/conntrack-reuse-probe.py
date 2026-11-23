"""Real same-tuple TCP reincarnation after the HTTP server actively closes."""
import json
import socket
import time

# The client's own kernel still holds the tuple after close() until the
# server's ACK of its FIN arrives (LAST_ACK). connect() on a tuple that is
# still held fails locally with EADDRNOTAVAIL, before any packet reaches the
# firewall. Wait for that ACK, bounded: an ACK the firewall dropped would keep
# the tuple held through FIN retransmissions and fail this wait instead.
LOCAL='321412C6:BC57'   # 198.18.20.50:48215, /proc/net/tcp byte order
REMOTE='FE0A12C6:238E'  # 198.18.10.254:9102
RELEASE_BOUND=2.0

def tuple_held():
    with open('/proc/net/tcp') as table:
        next(table)
        return any(row.split()[1:3]==[LOCAL,REMOTE] for row in table)

def wait_released():
    began=time.monotonic()
    while tuple_held():
        if time.monotonic()-began>RELEASE_BOUND:
            raise TimeoutError('client tuple still held after close')
        time.sleep(.005)
    return time.monotonic()-began

observations=[]
release_waits=[]
started=time.monotonic()
for attempt in range(40):
    connection=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    connection.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    connection.settimeout(2)
    stage='bind'
    try:
        connection.bind(('198.18.20.50',48215))
        stage='connect'
        connection.connect(('198.18.10.254',9102))
        stage='exchange-and-server-close'
        connection.sendall(b'GET /same-tuple-reuse HTTP/1.0\r\nHost: qa-reference\r\nConnection: close\r\n\r\n')
        response=b''
        while True:
            chunk=connection.recv(4096)
            if not chunk:break
            response+=chunk
        headers,body=response.split(b'\r\n\r\n',1)
        assert headers.startswith(b'HTTP/1.0 200'),headers
        actual=json.loads(body)
        assert actual['peer']=='198.18.20.50',actual
        observations.append({'attempt':attempt,'source_port':48215,'peer':actual['peer'],'server_EOF':True})
    except Exception as error:
        print(json.dumps({'status':'failed','stage':stage,'attempt':attempt,'completed_reuses':len(observations),
                          'error':type(error).__name__,'elapsed':time.monotonic()-started}),flush=True)
        raise
    finally:
        connection.close()
    # The close handshake must finish on the client before the tuple can be
    # reused. Bounded far below the unchanged default 30 second firewall
    # closing timeout; no state is flushed.
    stage='close-handshake'
    try:
        release_waits.append(wait_released())
    except Exception as error:
        print(json.dumps({'status':'failed','stage':stage,'attempt':attempt,'completed_reuses':len(observations),
                          'error':type(error).__name__,'elapsed':time.monotonic()-started}),flush=True)
        raise
elapsed=time.monotonic()-started
assert elapsed<20,elapsed
print(json.dumps({'status':'passed','same_tuple_connections':40,'elapsed':elapsed,
                  'no_NAT_or_state_reset':True,'max_close_handshake':max(release_waits),
                  'observations':observations}),flush=True)
