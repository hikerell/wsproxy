import struct
import socket
import binascii
import logging

logger = logging.getLogger(__name__)

class SocksV5(object):
    VERSION = 0x05
    CMD_CONNECT      = 0x01
    CMD_BIND         = 0x02
    CMD_UDPASSOCIATE = 0x03
    ATYP_IPv4       = 0x01
    ATYP_DOMAINNAME = 0x03
    ATYP_IPv6       = 0x04

    @classmethod
    def parse_request(cls, data: bytes):
        req = {
            'VER' : None,
            'CMD' : None,
            'RSV' : None, 
            'ATYP' : None, 
            'DST.ADDR' : None, 
            'DST.PORT' : None
        }
        try:
            req['VER'], req['CMD'], req['RSV'], req['ATYP'] = data[0], data[1], data[2], data[3]
            if req['ATYP'] == SocksV5.ATYP_IPv4:
                req['DST.ADDR'] = socket.inet_ntoa(data[4:8])
                req['DST.PORT'] = struct.unpack('>H', data[8:10])[0]
            elif req['ATYP'] == SocksV5.ATYP_IPv6:
                req['DST.ADDR'] = socket.inet_ntop(socket.AF_INET6, data[4:20])
                req['DST.PORT'] = struct.unpack('>H', data[20:22])[0]
            elif req['ATYP'] == SocksV5.ATYP_DOMAINNAME:
                name_size = data[4]
                req['DST.ADDR'] = data[5:5+name_size].decode('utf-8')
                req['DST.PORT'] = struct.unpack('>H', data[5+name_size:5+name_size+2])[0]
            else:
                print(f'parse_request unexcept ATYP:{req["ATYP"]} data:{binascii.b2a_hex(data)}')
                return None
            print(f"socks req: {req}") 
            return req
        except Exception as e:
            print(f'parse_request error:{e} data:{binascii.b2a_hex(data)}')
            logger.exception(e)
            return None

