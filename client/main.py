import random
import asyncio
import websockets
import logging
import traceback
import struct
import socket
from common import helper
from common.crypt import AesEcbCipher as Cipher
from .socks import SocksV5
from . import wsbridge

logger = logging.getLogger(__name__)

SOCKS_VERSION = 0x05

async def socks5_tcp_handler(cfg, reader, writer):
    # print("socks5_tcp_handler ...")
    """ 
    参考：https://github.com/dyboy2017/DYPROXY
    """
    """
    一、客户端认证请求
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     |  1~255   |
        +----+----------+----------+
    """
    header = await reader.read(2)
    # logger.info(f"header: {header.hex()}")
    VER, NMETHODS = struct.unpack("!BB", header)
    # 设置socks5协议，METHODS字段的数目大于0
    assert VER == SOCKS_VERSION, 'SOCKS版本错误'
    if VER != 0x05:
        logger.info(f'socks VER={VER}')
        return None
    if NMETHODS != 0x00:
        METHODS = await reader.read(NMETHODS)
        # logger.info(f'socks METHODS={METHODS}')
    # logger.info(f'socks VER={VER} NMETHODS=f{NMETHODS} METHODS={METHODS}')
    # print("ssocks rsp no auth ...")

    """
    二、服务端回应认证
        +----+--------+
        |VER | METHOD |
        +----+--------+
        | 1  |   1    |
        +----+--------+
    """
    writer.write(b'\x05\00')
    await writer.drain()
    # logger.debug('socks stage auth success!')
    

    # data = await reader.read(1024)
    # if not data:
    #     return None
    # logger.debug(f'socks stage request data: {data.hex()}')
    # req = SocksV5.parse_request(data)
    # logger.debug(f'socks stage request: {req}')
    # if not req or req['CMD'] != SocksV5.CMD_CONNECT:
    #     logger.debug(f'socks5 tcp request data unknown {data}')
    #     writer.write(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x04\xd2')
    #     return await writer.drain()

    """
    三、客户端连接请求(连接目的网络)
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  |   1   |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
    """
    data = await reader.read(4)
    version, cmd, _, address_type = struct.unpack("!BBBB", data)
    if address_type == 1:       # IPv4
        # 转换IPV4地址字符串（xxx.xxx.xxx.xxx）成为32位打包的二进制格式（长度为4个字节的二进制字符串）
        data = await reader.read(4)
        address: str = socket.inet_ntoa(data)
    elif address_type == 3:     # Domain
        data: bytes = await reader.read(1)
        # print(f"data is {data} type is {type(data)}")
        domain_length = data[0]
        data: bytes = await reader.read(domain_length)
        address: str = data.decode()
    else:
        print(f"socks unsupport address_type: {address_type}")
        return
    
    data = await reader.read(2)
    port = struct.unpack('!H', data)[0]

    # print(f"socks cmd: {cmd} target {address}:{port}")

    """
    四、服务端回应连接
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  |   1   |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
    """
    # 响应，只支持CONNECT请求
    if cmd != 1:
        print(f"socks unsupport cmd: {address_type}")
        return
    
    bridge = wsbridge.WebsocketBridge(cfg, reader, writer)

    state = await bridge.open_tunnel(address, port)

    if state!=wsbridge.TUNNEL_STATE_ESTABLISHED:
        writer.write(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x04\xd2')
        return await writer.drain()

    writer.write(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x04\xd2')
    await writer.drain()
    # logger.debug('socks stage request success!')

    try:
        await bridge.transfer()
    except Exception as e:
        #logger.exception(e)
        #logger.debug('force to close socks client reader/writer for the unexcepted exception')
        writer.close()
        await writer.wait_closed()

async def socks5_udp_handler(cfg, reader, writer):
    pass

async def http_proxy_handler(cfg, reader, writer):
    data = await reader.read(1024)
    logger.debug(f'request data: {data}')
    method, host, port, data = helper.rebuild_http_request(data)

    logger.debug(f'request domain: {host}:{port}')
    bridge = wsbridge.WebsocketBridge(cfg, reader, writer)

    state = await bridge.open_tunnel(host, port)
    if state != wsbridge.TUNNEL_STATE_ESTABLISHED:
        response_head = 'HTTP/1.0 500 Internal Server Error\r\nContent-Type: text/html\r\nContent-Length: %d'
        response_body = ''
        if state == wsbridge.TUNNEL_STATE_NO_SERVER:
            response_body += '********************************' + '\r\n'
            response_body += '*    Proxy Error     *' + '\r\n'
            response_body += '********************************' + '\r\n\r\n'
            response_body += 'no server avaliable' + '\r\n'
        elif state == wsbridge.TUNNEL_STATE_NO_RESPONSE:
            thost, tport = bridge.selected_tunnel_server['ip'], bridge.selected_tunnel_server['port']
            response_body += '********************************' + '\r\n'
            response_body += '*    Proxy Error     *' + '\r\n'
            response_body += '********************************' + '\r\n\r\n'
            response_body += 'tunnel server %s:%d no response'%(thost, tport) + '\r\n'
        elif state == wsbridge.TUNNEL_STATE_WRONG_PASSWORD:
            thost, tport = bridge.selected_tunnel_server['ip'], bridge.selected_tunnel_server['port']
            response_body += '********************************' + '\r\n'
            response_body += '*    Proxy Error     *' + '\r\n'
            response_body += '********************************' + '\r\n\r\n'
            response_body += 'tunnel server %s:%d wrong password'%(thost, tport) + '\r\n'
        elif state == wsbridge.TUNNEL_STATE_WRONG_CONNECT:
            thost, tport = bridge.selected_tunnel_server['ip'], bridge.selected_tunnel_server['port']
            response_body += '********************************' + '\r\n'
            response_body += '*    Proxy Error     *' + '\r\n'
            response_body += '********************************' + '\r\n\r\n'
            response_body += 'tunnel server %s:%d wrong connect'%(thost, tport) + '\r\n'

        payload = response_head%len(response_body) + '\r\n\r\n' + response_body
        print(payload)
        writer.write(payload.encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        return False

    if method==b'CONNECT':
        # reply connect, need fix
        writer.write(b'HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n')
        await writer.drain()
    else:
        #print('send http proxy data ...')
        await bridge.send_data(data)
    
    try:
        await bridge.transfer()
    except Exception as e:
        #logger.exception(e)
        #logger.debug('force to close socks client reader/writer for the unexcepted exception')
        writer.close()
        await writer.wait_closed()


async def http_pac_handler(cfg, reader, writer):
    data = await reader.read(1024)
    local_ip = writer.get_extra_info('sockname')[0]
    logger.info('request pac: response it with local socks server ip: %s' % local_ip)
    template = """
function FindProxyForURL(url, host)
{
    url  = url.toLowerCase();
    host = host.toLowerCase();

    if (isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")
      || isInNet(dnsResolve(host), "172.16.0.0",  "255.240.0.0")
      || isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0")
      || isInNet(dnsResolve(host), "127.0.0.0", "255.255.255.0")
    ) {
      return "DIRECT";
    }

    return "SOCKS LOCAL_IP:1080";
}
"""
    response_head = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close'
    response_body = template.replace('LOCAL_IP', local_ip)
    payload = response_head%len(response_body) + '\r\n\r\n' + response_body
    writer.write(payload.encode())
    await writer.drain()
    writer.close()
    await writer.wait_closed()
    return False

async def start_socks5_tcp_server(cfg):
    host, port = cfg['client']['socks']['host'], cfg['client']['socks']['port']
    server = await asyncio.start_server(lambda r,w: socks5_tcp_handler(cfg, r, w), host, port)
    host = server.sockets[0].getsockname()[0]
    logger.info(f'client socks-tcp-server listen on {host}:{port} ...')
    async with server:
        await server.serve_forever()
    logger.info(f'client socks-tcp-server closed ...')

async def start_socks5_udp_server(cfg):
    host, port = cfg['client']['socks']['host'], cfg['client']['socks']['port']
    logger.info(f'client socks-udp-server listen on {host}:{port} ...')
    #server = await asyncio.start_server(udp_server, host, port)
    #async with server:
    #    await server.serve_forever()
    logger.info(f'client socks-udp-server closed ...')

async def start_http_proxy_server(cfg):
    host, port = cfg['client']['http']['host'], cfg['client']['http']['port']
    server = await asyncio.start_server(lambda r,w: http_proxy_handler(cfg, r, w), host, port)
    host = server.sockets[0].getsockname()[0]
    logger.info(f'client http-proxy-server listen on {host}:{port} ...')
    async with server:
        await server.serve_forever()
    logger.info(f'client http-proxy-server closed ...')

async def start_pac_server(cfg):
    host, port = cfg['client']['pac']['host'], cfg['client']['pac']['port']
    server = await asyncio.start_server(lambda r,w: http_pac_handler(cfg, r, w), host, port)
    host = server.sockets[0].getsockname()[0]
    logger.info(f'client http-pac-server listen on {host}:{port} ...')
    async with server:
        await server.serve_forever()
    logger.info(f'client http-pac-server closed ...')

async def start_local_server(cfg):
    await asyncio.wait([
        start_socks5_tcp_server(cfg),
        #start_socks5_udp_server(cfg),
        start_http_proxy_server(cfg),
        start_pac_server(cfg)
        ])
    print('client end local server ...')

def start(cfg):
    asyncio.run(start_local_server(cfg))
