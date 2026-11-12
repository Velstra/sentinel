"""Real same-tuple TCP reincarnation after the HTTP server actively closes."""
import json
import socket
import time

observations=[]
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
    # Allow the actual close handshake to finish. This is far below the
    # unchanged default30second firewall closing timeout; no state is flushed.
    time.sleep(.01)
elapsed=time.monotonic()-started
assert elapsed<20,elapsed
print(json.dumps({'status':'passed','same_tuple_connections':40,'elapsed':elapsed,
                  'no_NAT_or_state_reset':True,'observations':observations}),flush=True)
