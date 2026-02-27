import asyncio
import logging
import struct
import socket
import math
import json
import sys
import time
import aiohttp
import argparse
from wsproxy.crypto import Cipher
from wsproxy.utils import normalize_host
# from wsproxy.utils import hexdump

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("client")


class GlobalUDPTunnelManager:
    def __init__(self, ws_url, cipher, pool_size=4):
        self.ws_url = ws_url
        self.cipher = cipher
        self.pool_size = pool_size
        self.conns = []  # list of dict: {"ws": ws, "read_task": task}
        self.sessions = {}  # session_id -> protocol
        self.sid_to_conn_idx = {}  # session_id -> conn_idx
        self.lock = asyncio.Lock()
        self.next_session_id = 1
        self.next_conn_index = 0
        self._shared_session = None
        self.conn_init_locks = []

    async def _get_session(self):
        if self._shared_session is None or self._shared_session.closed:
            self._shared_session = aiohttp.ClientSession()
        return self._shared_session

    async def close(self):
        async with self.lock:
            for conn in self.conns:
                if conn:
                    await conn["ws"].close()
                    conn["read_task"].cancel()
            if self._shared_session:
                await self._shared_session.close()
            self.conns = []

    async def get_session_id(self):
        async with self.lock:
            sid = self.next_session_id
            self.next_session_id += 1
            return sid

    async def register(self, protocol):
        sid = await self.get_session_id()
        async with self.lock:
            self.sessions[sid] = protocol
            # Assign a connection in round-robin
            conn_idx = self.next_conn_index
            self.next_conn_index = (self.next_conn_index + 1) % self.pool_size
            self.sid_to_conn_idx[sid] = conn_idx
        return sid

    def unregister(self, sid):
        if sid in self.sessions:
            del self.sessions[sid]
        if sid in self.sid_to_conn_idx:
            del self.sid_to_conn_idx[sid]

    async def _ensure_conn(self, idx):
        if idx < len(self.conns) and self.conns[idx] and not self.conns[idx]["ws"].closed:
            return self.conns[idx]["ws"]

        # Expand conns list if needed
        while len(self.conns) <= idx:
            self.conns.append(None)
        while len(self.conn_init_locks) <= idx:
            self.conn_init_locks.append(asyncio.Lock())

        # Avoid concurrent reconnect attempts for the same tunnel index
        async with self.conn_init_locks[idx]:
            if idx < len(self.conns) and self.conns[idx] and not self.conns[idx]["ws"].closed:
                return self.conns[idx]["ws"]

            session = await self._get_session()
            try:
                ws = await session.ws_connect(self.ws_url, heartbeat=30)
                # Handshake for UDP Tunnel
                req = json.dumps({"cmd": "udp_tunnel"}).encode("utf-8")
                await ws.send_bytes(self.cipher.encrypt(req))

                resp = await ws.receive()
                if resp.type == aiohttp.WSMsgType.BINARY:
                    data = self.cipher.decrypt(resp.data)
                    msg = json.loads(data)
                    if msg.get("status") != "ok":
                        raise Exception(f"Server rejected UDP tunnel: {msg}")
                else:
                    raise Exception("Invalid handshake response")

                read_task = asyncio.create_task(self.read_loop(ws, idx))
                self.conns[idx] = {"ws": ws, "read_task": read_task}
                logger.info(f"UDP Tunnel connection {idx} connected")
                return ws

            except Exception as e:
                logger.error(f"Failed to connect UDP tunnel {idx}: {e}")
                self.conns[idx] = None
                raise

    async def send(self, session_id, data):
        conn_idx = self.sid_to_conn_idx.get(session_id)
        if conn_idx is None:
            return

        try:
            ws = await self._ensure_conn(conn_idx)
            # Packet: [SessionID 4B] + Data
            packet = struct.pack("!I", session_id) + data
            encrypted = self.cipher.encrypt(packet)
            await ws.send_bytes(encrypted)
        except Exception as e:
            logger.error(f"Tunnel send error on session {session_id}: {e}")
            if conn_idx < len(self.conns):
                self.conns[conn_idx] = None

    async def read_loop(self, ws, idx):
        try:
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    try:
                        decrypted = self.cipher.decrypt(msg.data)
                        if len(decrypted) < 4:
                            continue
                        
                        # Use memoryview to avoid copies during unpacking
                        # mv_decrypted = memoryview(decrypted)
                        mv_decrypted = decrypted
                        sid = struct.unpack("!I", mv_decrypted[:4])[0]
                        payload = mv_decrypted[4:]

                        if sid in self.sessions:
                            self.sessions[sid].receive_from_tunnel(payload)
                    except Exception as e:
                        logger.error(f"Tunnel {idx} read error: {e}")
                elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    break
        except Exception as e:
            logger.error(f"Tunnel {idx} connection lost: {e}")
        finally:
            # logger.info(f"UDP Tunnel {idx} closed")
            async with self.lock:
                if idx < len(self.conns) and self.conns[idx] and self.conns[idx]["ws"] == ws:
                    self.conns[idx] = None


class GlobalTCPTunnelManager:
    def __init__(self, ws_url, cipher, pool_size=4):
        self.ws_url = ws_url
        self.cipher = cipher
        self.pool_size = pool_size
        self.conns = []  # list of dict: {"ws": ws, "read_task": task}
        self.tcp_relay_sessions = {}
        self.sid_to_conn_idx = {}
        self.lock = asyncio.Lock()
        self.next_session_id = 1
        self.next_conn_index = 0
        self.pending_opens = {}
        self._shared_session = None

    async def _get_session(self):
        if self._shared_session is None or self._shared_session.closed:
            self._shared_session = aiohttp.ClientSession()
        return self._shared_session

    async def close(self):
        async with self.lock:
            for conn in self.conns:
                if conn:
                    await conn["ws"].close()
                    conn["read_task"].cancel()
            if self._shared_session:
                await self._shared_session.close()
            self.conns = []

    async def get_session_id(self):
        async with self.lock:
            sid = self.next_session_id
            self.next_session_id += 1
            return sid

    async def _ensure_conn(self, idx):
        if idx < len(self.conns) and self.conns[idx] and not self.conns[idx]["ws"].closed:
            return self.conns[idx]["ws"]

        while len(self.conns) <= idx:
            self.conns.append(None)

        session = await self._get_session()
        try:
            ws = await session.ws_connect(self.ws_url, heartbeat=30)
            req = json.dumps({"cmd": "tcp_tunnel"}).encode("utf-8")
            await ws.send_bytes(self.cipher.encrypt(req))
            resp = await ws.receive()
            if resp.type == aiohttp.WSMsgType.BINARY:
                data = self.cipher.decrypt(resp.data)
                msg = json.loads(data)
                if msg.get("status") != "ok":
                    raise Exception(f"Server rejected TCP tunnel: {msg}")
            else:
                raise Exception("Invalid handshake response")
            read_task = asyncio.create_task(self.read_loop(ws, idx))
            self.conns[idx] = {"ws": ws, "read_task": read_task}
            return ws
        except Exception as e:
            logger.error(f"Failed to connect TCP tunnel {idx}: {e}")
            self.conns[idx] = None
            raise

    async def open_session(self, host, port, stream):
        sid = await self.get_session_id()
        async with self.lock:
            conn_idx = self.next_conn_index
            self.next_conn_index = (self.next_conn_index + 1) % self.pool_size
            self.sid_to_conn_idx[sid] = conn_idx
            
        try:
            ws = await self._ensure_conn(conn_idx)
        except Exception as e:
            logger.error(f"Failed to open TCP session [ensure_conn] for {host}:{port}: {e}")
            return None

        # logger.info(f"tcp tunnenel: open session with stream: {stream}")
        self.tcp_relay_sessions[sid] = stream
        fut = asyncio.get_running_loop().create_future()
        self.pending_opens[sid] = fut
        payload = {"type": "open", "sid": sid, "host": normalize_host(host), "port": port}
        data = json.dumps(payload).encode("utf-8")
        await ws.send_bytes(self.cipher.encrypt(data))
        try:
            await asyncio.wait_for(fut, timeout=10)
            return sid
        except Exception as e:
            logger.error(f"Failed to open TCP session [wait_for] for {host}:{port}: {e}")
            logger.exception(e)
            self.tcp_relay_sessions.pop(sid, None)
            self.pending_opens.pop(sid, None)
            self.sid_to_conn_idx.pop(sid, None)
            return None

    async def close_session(self, sid):
        # logger.info(f"**************** close session: sid={sid}")
        conn_idx = self.sid_to_conn_idx.get(sid)
        if conn_idx is not None and conn_idx < len(self.conns) and self.conns[conn_idx]:
            ws = self.conns[conn_idx]["ws"]
            payload = {"type": "close", "sid": sid}
            data = json.dumps(payload).encode("utf-8")
            try:
                await ws.send_bytes(self.cipher.encrypt(data))
            except Exception:
                pass
        
        self.tcp_relay_sessions.pop(sid, None)
        self.pending_opens.pop(sid, None)
        self.sid_to_conn_idx.pop(sid, None)

    async def send_data(self, sid, data):
        conn_idx = self.sid_to_conn_idx.get(sid)
        if conn_idx is None:
            return
        
        try:
            ws = await self._ensure_conn(conn_idx)
            packet = struct.pack("!I", sid) + data
            encrypted = self.cipher.encrypt(packet)
            await ws.send_bytes(encrypted)
        except Exception:
            if conn_idx < len(self.conns):
                self.conns[conn_idx] = None

    async def read_loop(self, ws, idx):
        try:
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    decrypted = self.cipher.decrypt(msg.data)
                    try:
                        # logger.info(f"receive decrypted data: {decrypted}")
                        # logger.info(f"receive decrypted data with sessions: {self.tcp_relay_sessions}")
                        j = json.loads(decrypted)
                        t = j.get("type")
                        # logger.info(f"tcp tunnel: proxy-client receive {t} {type(t)}")
                        # logger.info(decrypted)
                        if t == "open_ack":
                            sid = j.get("sid")
                            status = j.get("status", "ok")
                            fut = self.pending_opens.get(sid)
                            if fut and not fut.done():
                                if status == "ok":
                                    fut.set_result(True)
                                else:
                                    fut.set_exception(
                                        RuntimeError(j.get("message", "open session failed"))
                                    )
                        elif t == "close":
                            sid = j.get("sid")
                            # logger.info(f"tcp tunnel: close with sid {sid} {type(sid)} stream: {self.tcp_relay_sessions}")
                            stream = self.tcp_relay_sessions.pop(sid, None)
                            self.sid_to_conn_idx.pop(sid, None)
                            # logger.info(f"stream: {stream}")
                            if stream:
                                try:
                                    stream.writer.close()
                                    await stream.writer.wait_closed()
                                except Exception:
                                    pass
                    except Exception as e:
                        # logger.exception(e)
                        if len(decrypted) < 4:
                            continue
                        
                        # Use memoryview to avoid copies
                        mv_decrypted = memoryview(decrypted)
                        sid = struct.unpack("!I", mv_decrypted[:4])[0]
                        payload = mv_decrypted[4:]
                        
                        # logger.info(f"before sessions.get {sid}: {self.tcp_relay_sessions}")
                        stream = self.tcp_relay_sessions.get(sid)
                        # logger.info(f"after sessions.get {sid}: {self.tcp_relay_sessions}")
                        if stream:
                            try:
                                stream.writer.write(payload)
                                await stream.writer.drain()
                            except Exception as e:
                                logger.error(e)
                                pass
                        # logger.info(f"continue ... with sessions: {self.tcp_relay_sessions}")
                elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    # logger.info(f"msg.type: {msg.type}")
                    break
        except Exception as e:
            logger.exception(e)
        finally:
            # logger.info(f"************** ws end ****************")
            async with self.lock:
                if idx < len(self.conns) and self.conns[idx] and self.conns[idx]["ws"] == ws:
                    self.conns[idx] = None


class UDPClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, manager):
        self.manager = manager
        self.transport = None
        self.client_addr = None
        self.session_id = None
        self.last_active_time = None
        self.init_time = time.time()
        self.send_queue = asyncio.Queue(maxsize=2048)
        self.sender_task = None

    def connection_made(self, transport):
        self.transport = transport
        asyncio.create_task(self.register())

    async def register(self):
        self.session_id = await self.manager.register(self)
        self.sender_task = asyncio.create_task(self._sender_loop())

    async def _sender_loop(self):
        try:
            while True:
                payload = await self.send_queue.get()
                if self.session_id:
                    await self.manager.send(self.session_id, payload)
                self.send_queue.task_done()
        except asyncio.CancelledError:
            pass

    def datagram_received(self, data, addr):
        self.last_active_time = time.time()
        # logger.info(f"datagram_received: {len(data)} from {addr}\n{hexdump(data)}")
        self.client_addr = addr
        # Strip RSV(2)+FRAG(1) -> 3 bytes
        if len(data) < 3:
            return
        payload = data[3:]
        if self.session_id:
            try:
                self.send_queue.put_nowait(payload)
            except asyncio.QueueFull:
                pass

    def connection_lost(self, exc):
        if self.sender_task:
            self.sender_task.cancel()

    def receive_from_tunnel(self, data):
        self.last_active_time = time.time()
        # logger.info(f"receive_from_tunnel: {len(data)}\n{hexdump(data)}")
        packet = b"\x00\x00\x00" + data
        if self.transport and self.client_addr:
            self.transport.sendto(packet, self.client_addr)

    def is_active(self):
        # 当30秒无数据发送，标记为不活跃
        now = time.time()
        if self.last_active_time is None:
            if now - self.init_time > 10:
                return False
        elif now - self.last_active_time > 30:
                return False
        return True


class Socks5Proxy:
    def __init__(self, ws_url, local_host="0.0.0.0", local_port=1080, password=None, pool_size=4):
        self.ws_url = ws_url
        self.local_host = local_host
        self.local_port = local_port
        self.cipher = Cipher(password)
        self.pool_size = pool_size
        self.tcp_manager = GlobalTCPTunnelManager(ws_url, self.cipher, pool_size=pool_size)
        self.udp_manager = GlobalUDPTunnelManager(ws_url, self.cipher, pool_size=max(math.floor(pool_size / 2), 1))

    async def handle_client(self, reader, writer):
        try:
            # 1. Negotiate Authentication
            data = await reader.read(2)
            if not data or data[0] != 0x05:
                writer.close()
                await writer.wait_closed()
                return

            nmethods = data[1]
            await reader.read(nmethods)
            writer.write(b"\x05\x00")
            await writer.drain()

            # 2. Handle Request
            header = await reader.read(4)
            if not header or len(header) < 4:
                writer.close()
                await writer.wait_closed()
                return

            ver, cmd, rsv, atyp = header

            if cmd == 0x01:  # CONNECT
                await self.handle_connect(reader, writer, atyp)
            elif cmd == 0x03:  # UDP ASSOCIATE
                await self.handle_udp_associate(reader, writer, atyp)
            else:
                logger.warning(f"Socks5 Proxy Not Support CMD {cmd}")
                self.send_reply(writer, 0x07)  # Command not supported
                writer.close()
                await writer.wait_closed()

        except Exception as e:
            logger.exception(e)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

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
            await writer.wait_closed()
            return

        logger.info(f"[tcp] {dest_addr}:{dest_port}")
        sid = await self.tcp_manager.open_session(
            dest_addr, dest_port, type("S", (), {"writer": writer})()
        )
        if not sid:
            logger.warning(f"Failed to open TCP session for {dest_addr}:{dest_port}")
            self.send_reply(writer, 0x01)
            writer.close()
            await writer.wait_closed()
            return

        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()

        async def client_to_tunnel():
            try:
                while True:
                    try:
                        # logger.info(f"TCP client to tunnel: read and wait 600s for {dest_addr}:{dest_port}")
                        data = await asyncio.wait_for(reader.read(16384), timeout=600)
                    except asyncio.TimeoutError:
                        # logger.warning(f"TCP client to tunnel: timeout with SID {sid} for {dest_addr}:{dest_port}")
                        break

                    if not data:
                        # logger.info(f"*********** no data")
                        break
                    # logger.info(f"TCP client to tunnel: send {len(data)} bytes for {dest_addr}:{dest_port}")
                    await self.tcp_manager.send_data(sid, data)
            except Exception as e:
                logger.error(f"Client to tunnel error for SID {sid}: {e}")
            finally:
                await self.tcp_manager.close_session(sid)
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        await client_to_tunnel()

    async def handle_udp_associate(self, reader, writer, atyp):
        await self.read_addr(reader, atyp)

        loop = asyncio.get_running_loop()

        # 获取客户端建立 TCP 时连接的代理服务器 IP
        server_ip = writer.get_extra_info('sockname')[0]

        # 1. 绑定到 0.0.0.0 以接受外部连接
        udp_client_protocol = UDPClientProtocol(self.udp_manager)
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: udp_client_protocol, 
            local_addr=('0.0.0.0', 0)
        )
        bound_port = transport.get_extra_info("sockname")[1]

        # 2. 回复给客户端它能连通的 IP
        reply = (
            struct.pack("!BBBB", 5, 0, 0, 1)
            + socket.inet_aton(server_ip) # 不要硬编码 127.0.0.1
            + struct.pack("!H", bound_port)
        )

        writer.write(reply)
        await writer.drain()

        # 3. Keep TCP open to maintain association
        try:
            while True:
                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=3)
                    if not data:
                        break
                except asyncio.TimeoutError:
                    # 检查UDP连接是否活跃
                    if not udp_client_protocol.is_active():
                        break
        except Exception as e:
            logger.warning(f"UDP associate TCP connection {server_ip}:{bound_port} error:{e}")
        finally:
            logger.warning(f"UDP associate TCP connection {server_ip}:{bound_port} closing ...")
            if protocol.session_id:
                self.udp_manager.unregister(protocol.session_id)
            transport.close()
            writer.close()
            await writer.wait_closed()

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
        return normalize_host(dest_addr), dest_port

    def send_reply(self, writer, rep_code):
        reply = struct.pack("!BBBB", 5, rep_code, 0, 1) + b"\x00\x00\x00\x00\x00\x00"
        writer.write(reply)

    async def start(self):
        server = await asyncio.start_server(
            self.handle_client, self.local_host, self.local_port
        )
        for sock in server.sockets:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        logger.info(f"SOCKS5 client listening on {self.local_host}:{self.local_port}")
        logger.info(f"Forwarding to {self.ws_url} with {self.pool_size} websockets")

        async with server:
            try:
                await server.serve_forever()
            finally:
                await self.close()

    async def close(self):
        await self.tcp_manager.close()
        await self.udp_manager.close()


def run_client(server, port=1080, password=None, pool_size=4):
    ws_url = f"http://{server}/proxy"
    proxy = Socks5Proxy(ws_url, local_host="0.0.0.0", local_port=port, password=password, pool_size=pool_size)
    try:
        asyncio.run(proxy.start())
    except KeyboardInterrupt:
        pass


def main():
    if sys.platform != "win32":
        try:
            import uvloop
            uvloop.install()
            logger.info("uvloop installed")
        except ImportError:
            logger.warning("uvloop not installed, using default event loop")

    parser = argparse.ArgumentParser("wsproxy client")
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

    parser.add_argument(
        "--pool-size",
        type=int,
        default=8,
        help="Number of WebSocket connections in the pool (default: 8)",
    )

    args = parser.parse_args()
    run_client(
        server=args.server,
        port=args.port,
        password=args.password,
        pool_size=args.pool_size,
    )


if __name__ == "__main__":
    main()
