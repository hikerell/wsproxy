import asyncio
import logging
import struct
import socket
import json
import aiohttp
import argparse
from wsproxy.crypto import Cipher

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("client")


class GlobalUDPTunnelManager:
    def __init__(self, ws_url, cipher):
        self.ws_url = ws_url
        self.cipher = cipher
        self.ws = None
        self.session = None
        self.sessions = {}  # session_id -> protocol
        self.lock = asyncio.Lock()
        self.read_task = None
        self.next_session_id = 1

    async def get_session_id(self):
        sid = self.next_session_id
        self.next_session_id += 1
        return sid

    async def register(self, protocol):
        sid = await self.get_session_id()
        self.sessions[sid] = protocol
        return sid

    def unregister(self, sid):
        if sid in self.sessions:
            del self.sessions[sid]

    async def ensure_connected(self):
        if self.ws and not self.ws.closed:
            return

        self.session = aiohttp.ClientSession()
        try:
            self.ws = await self.session.ws_connect(self.ws_url)

            # Handshake for UDP Tunnel
            req = json.dumps({"cmd": "udp_tunnel"}).encode("utf-8")
            await self.ws.send_bytes(self.cipher.encrypt(req))

            resp = await self.ws.receive()
            if resp.type == aiohttp.WSMsgType.BINARY:
                data = self.cipher.decrypt(resp.data)
                msg = json.loads(data)
                if msg.get("status") != "ok":
                    raise Exception(f"Server rejected UDP tunnel: {msg}")
            else:
                raise Exception("Invalid handshake response")

            self.read_task = asyncio.create_task(self.read_loop())
            logger.info("Global UDP Tunnel connected")

        except Exception as e:
            logger.error(f"Failed to connect UDP tunnel: {e}")
            if self.session:
                await self.session.close()
            self.ws = None
            raise

    async def send(self, session_id, data):
        async with self.lock:
            try:
                await self.ensure_connected()
                # Packet: [SessionID 4B] + Data
                packet = struct.pack("!I", session_id) + data
                encrypted = self.cipher.encrypt(packet)
                await self.ws.send_bytes(encrypted)
            except Exception as e:
                logger.error(f"Tunnel send error: {e}")
                self.ws = None

    async def read_loop(self):
        try:
            async for msg in self.ws:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    try:
                        decrypted = self.cipher.decrypt(msg.data)
                        if len(decrypted) < 4:
                            continue
                        sid = struct.unpack("!I", decrypted[:4])[0]
                        payload = decrypted[4:]

                        if sid in self.sessions:
                            self.sessions[sid].receive_from_tunnel(payload)
                    except Exception as e:
                        logger.error(f"Tunnel read error: {e}")
                elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    break
        except Exception as e:
            logger.error(f"Tunnel connection lost: {e}")
        finally:
            self.ws = None
            logger.info("UDP Tunnel closed")


class GlobalTCPTunnelManager:
    def __init__(self, ws_url, cipher):
        self.ws_url = ws_url
        self.cipher = cipher
        self.ws = None
        self.session = None
        self.sessions = {}
        self.lock = asyncio.Lock()
        self.read_task = None
        self.next_session_id = 1
        self.pending_opens = {}

    async def get_session_id(self):
        sid = self.next_session_id
        self.next_session_id += 1
        return sid

    async def ensure_connected(self):
        if self.ws and not self.ws.closed:
            return

        self.session = aiohttp.ClientSession()
        try:
            self.ws = await self.session.ws_connect(self.ws_url)
            req = json.dumps({"cmd": "tcp_tunnel"}).encode("utf-8")
            await self.ws.send_bytes(self.cipher.encrypt(req))
            resp = await self.ws.receive()
            if resp.type == aiohttp.WSMsgType.BINARY:
                data = self.cipher.decrypt(resp.data)
                msg = json.loads(data)
                if msg.get("status") != "ok":
                    raise Exception(f"Server rejected TCP tunnel: {msg}")
            else:
                raise Exception("Invalid handshake response")
            self.read_task = asyncio.create_task(self.read_loop())
        except Exception as e:
            if self.session:
                await self.session.close()
            self.ws = None
            raise

    async def open_session(self, host, port, stream):
        await self.ensure_connected()
        sid = await self.get_session_id()
        self.sessions[sid] = stream
        fut = asyncio.get_running_loop().create_future()
        self.pending_opens[sid] = fut
        payload = {"type": "open", "sid": sid, "host": host, "port": port}
        data = json.dumps(payload).encode("utf-8")
        await self.ws.send_bytes(self.cipher.encrypt(data))
        try:
            await asyncio.wait_for(fut, timeout=10)
            return sid
        except Exception:
            self.sessions.pop(sid, None)
            self.pending_opens.pop(sid, None)
            return None

    async def close_session(self, sid):
        if not self.ws:
            return
        payload = {"type": "close", "sid": sid}
        data = json.dumps(payload).encode("utf-8")
        try:
            await self.ws.send_bytes(self.cipher.encrypt(data))
        except Exception:
            pass
        self.sessions.pop(sid, None)
        self.pending_opens.pop(sid, None)

    async def send_data(self, sid, data):
        async with self.lock:
            try:
                await self.ensure_connected()
                packet = struct.pack("!I", sid) + data
                encrypted = self.cipher.encrypt(packet)
                await self.ws.send_bytes(encrypted)
            except Exception:
                self.ws = None

    async def read_loop(self):
        try:
            async for msg in self.ws:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    try:
                        decrypted = self.cipher.decrypt(msg.data)
                        try:
                            j = json.loads(decrypted)
                            t = j.get("type")
                            if t == "open_ack":
                                sid = j.get("sid")
                                fut = self.pending_opens.get(sid)
                                if fut and not fut.done():
                                    fut.set_result(True)
                            elif t == "close":
                                sid = j.get("sid")
                                stream = self.sessions.pop(sid, None)
                                if stream:
                                    try:
                                        stream.writer.close()
                                    except Exception:
                                        pass
                        except Exception:
                            if len(decrypted) < 4:
                                continue
                            sid = struct.unpack("!I", decrypted[:4])[0]
                            payload = decrypted[4:]
                            stream = self.sessions.get(sid)
                            if stream:
                                try:
                                    stream.writer.write(payload)
                                    await stream.writer.drain()
                                except Exception:
                                    pass
                    except Exception:
                        pass
                elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    break
        except Exception:
            pass
        finally:
            self.ws = None


class UDPClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, manager):
        self.manager = manager
        self.transport = None
        self.client_addr = None
        self.session_id = None

    def connection_made(self, transport):
        self.transport = transport
        asyncio.create_task(self.register())

    async def register(self):
        self.session_id = await self.manager.register(self)

    def datagram_received(self, data, addr):
        self.client_addr = addr
        # Strip RSV(2)+FRAG(1) -> 3 bytes
        if len(data) < 3:
            return
        payload = data[3:]
        if self.session_id:
            asyncio.create_task(self.manager.send(self.session_id, payload))

    def receive_from_tunnel(self, data):
        packet = b"\x00\x00\x00" + data
        if self.transport and self.client_addr:
            self.transport.sendto(packet, self.client_addr)


class Socks5Proxy:
    def __init__(self, ws_url, local_host="127.0.0.1", local_port=1080, password=None):
        self.ws_url = ws_url
        self.local_host = local_host
        self.local_port = local_port
        self.cipher = Cipher(password)
        self.tcp_manager = GlobalTCPTunnelManager(ws_url, self.cipher)
        self.udp_manager = GlobalUDPTunnelManager(ws_url, self.cipher)

    async def handle_client(self, reader, writer):
        try:
            # 1. Negotiate Authentication
            data = await reader.read(2)
            if not data or data[0] != 0x05:
                writer.close()
                return

            nmethods = data[1]
            await reader.read(nmethods)
            writer.write(b"\x05\x00")
            await writer.drain()

            # 2. Handle Request
            header = await reader.read(4)
            if not header or len(header) < 4:
                return

            ver, cmd, rsv, atyp = header

            if cmd == 0x01:  # CONNECT
                await self.handle_connect(reader, writer, atyp)
            elif cmd == 0x03:  # UDP ASSOCIATE
                await self.handle_udp_associate(reader, writer, atyp)
            else:
                self.send_reply(writer, 0x07)  # Command not supported
                writer.close()

        except Exception as e:
            logger.error(f"Handler error: {e}")
            writer.close()

    async def send_ws_json(self, ws, data):
        json_bytes = json.dumps(data).encode("utf-8")
        encrypted = self.cipher.encrypt(json_bytes)
        await ws.send_bytes(encrypted)

    async def recv_ws_json(self, ws):
        msg = await ws.receive()
        if msg.type == aiohttp.WSMsgType.BINARY:
            decrypted = self.cipher.decrypt(msg.data)
            return json.loads(decrypted)
        elif msg.type == aiohttp.WSMsgType.TEXT:
            if self.cipher.aead:
                return json.loads(msg.data)
            return json.loads(msg.data)
        return None

    async def handle_connect(self, reader, writer, atyp):
        dest_addr, dest_port = await self.read_addr(reader, atyp)
        if not dest_addr:
            self.send_reply(writer, 0x08)
            writer.close()
            return

        sid = await self.tcp_manager.open_session(
            dest_addr, dest_port, type("S", (), {"writer": writer})()
        )
        if not sid:
            self.send_reply(writer, 0x01)
            writer.close()
            return

        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()

        async def client_to_tunnel():
            try:
                while True:
                    data = await reader.read(4096)
                    if not data:
                        break
                    await self.tcp_manager.send_data(sid, data)
            except Exception:
                pass
            await self.tcp_manager.close_session(sid)
            try:
                writer.close()
            except Exception:
                pass

        await client_to_tunnel()

    async def handle_udp_associate(self, reader, writer, atyp):
        await self.read_addr(reader, atyp)

        # 1. Bind a local UDP port
        loop = asyncio.get_running_loop()

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: UDPClientProtocol(self.udp_manager), local_addr=("127.0.0.1", 0)
        )

        local_udp_port = transport.get_extra_info("sockname")[1]
        logger.info(f"UDP Associate bound to 127.0.0.1:{local_udp_port}")

        # 2. Reply to client with BND.ADDR/PORT
        reply = (
            struct.pack("!BBBB", 5, 0, 0, 1)
            + socket.inet_aton("127.0.0.1")
            + struct.pack("!H", local_udp_port)
        )
        writer.write(reply)
        await writer.drain()

        # 3. Keep TCP open to maintain association
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
        except Exception:
            pass
        finally:
            if protocol.session_id:
                self.udp_manager.unregister(protocol.session_id)
            transport.close()
            writer.close()

    async def read_addr(self, reader, atyp):
        if atyp == 0x01:
            addr_bytes = await reader.read(4)
            dest_addr = socket.inet_ntoa(addr_bytes)
        elif atyp == 0x03:
            addr_len = (await reader.read(1))[0]
            dest_addr = (await reader.read(addr_len)).decode("utf-8")
        elif atyp == 0x04:
            addr_bytes = await reader.read(16)
            dest_addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        else:
            return None, None

        port_bytes = await reader.read(2)
        dest_port = struct.unpack("!H", port_bytes)[0]
        return dest_addr, dest_port

    def send_reply(self, writer, rep_code):
        reply = struct.pack("!BBBB", 5, rep_code, 0, 1) + b"\x00\x00\x00\x00\x00\x00"
        writer.write(reply)

    async def start(self):
        server = await asyncio.start_server(
            self.handle_client, self.local_host, self.local_port
        )
        logger.info(f"SOCKS5 client listening on {self.local_host}:{self.local_port}")
        logger.info(f"Forwarding to {self.ws_url}")

        async with server:
            await server.serve_forever()


def run_client(server, port=1080, password=None):
    ws_url = f"http://{server}/proxy"
    proxy = Socks5Proxy(ws_url, local_port=port, password=password)
    try:
        asyncio.run(proxy.start())
    except KeyboardInterrupt:
        pass


def main():
    parser = argparse.ArgumentParser(
        description="wsproxy: SOCKS5 over WebSocket Tunnel"
    )
    parser.add_argument(
        "--password", help="Encryption password (optional)", default=None
    )

    parser.add_argument(
        "--port", type=int, default=1080, help="Local SOCKS5 port (default: 1080)"
    )

    parser.add_argument(
        "--server",
        required=True,
        help="WebSocket Server (e.g., 127.0.0.1:10080)",
    )

    args = parser.parse_args()
    run_client(server=args.server, port=args.port, password=args.password)


if __name__ == "__main__":
    main()
