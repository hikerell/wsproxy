from urllib.parse import urlparse, urlunparse

def _build_http_request(method, path, version, headers, body):
    output = method + b' ' + path + b' ' + version + b'\r\n'
    for k, v in headers.items():
        output += k + b': ' + v + b'\r\n'
    output += b'\r\n'
    output += body
    return output

def _parse_http_request(data: bytes):
    head, body = data.split(b"\r\n\r\n")
    fields = head.split(b'\r\n')
    method, path, version = fields[0].split(b' ')
    fields = fields[1:]
    headers = {}
    for field in fields:
        field = field.strip()
        key = field.split(b':')[0]
        if key!=b'Proxy-Connection':
            value = b':'.join(field.split(b':')[1:])
            headers[key.strip()] = value.strip()
    
    method = method.strip().upper()

    host = None
    port = None
    if method==b'CONNECT':
        if b':' in path:
            host, port = path.split(b':')
        else:
            host = path
            port = b'80'
    elif path.startswith(b'http://'):
        u = urlparse(path)
        hostport = u.netloc.strip()
        if b':' in hostport:
            host, port = hostport.split(b':')
        else:
            host = hostport
            port = b'80'
        u = u._replace(scheme=b'')._replace(netloc=b'')
        path = urlunparse(u)
        #print(b'==== HTTP Request ====', data)
        data = _build_http_request(method, path, version, headers, body)
        #print(b'==== HTTP Rebuild ====:', data)
    elif path.startswith(b'https://'):
        hostport = urlparse(path).netloc.strip()
        if b':' in hostport:
            host, port = hostport.split(b':')
        else:
            host = hostport
            port = b'443'
        u = u._replace(scheme=b'')._replace(netloc=b'')
        path = urlunparse(u)
        #print(b'==== HTTP Request ====', data)
        data = _build_http_request(method, path, version, headers, body)
        #print(b'==== HTTP Rebuild ====:', data)
    elif b'Host' in headers:
        hostport = headers[b'Host']
        if b':' in hostport:
            host, port = hostport.split(b':')
        else:
            host = hostport
            port = b'80'
        #print(b'==== HTTP Request ====', data)
        data = _build_http_request(method, path, version, headers, body)
        #print(b'==== HTTP Rebuild ====:', data)
    
    host = host.strip().decode()
    port = int(port.strip())
    return method, host, port, data

def rebuild_http_request(data: bytes):
    try:
        return _parse_http_request(data)
    except Exception as e:
        print(f'parse_http_request failed: {e}')
        print(f'data: {data}')
        raise e