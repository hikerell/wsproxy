import asyncio
import logging
import json
import struct
import argparse
import socket
import sys
from aiohttp import web, WSMsgType
from wsproxy.utils import pack_addr, unpack_addr
from wsproxy.crypto import Cipher

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("server")


class UDPTunnelProtocol(asyncio.DatagramProtocol):
    def __init__(self, ws, cipher, session_id):
        self.ws = ws
        self.cipher = cipher
        self.session_id = session_id
        self.transport = None

    async def _setup(self):
        self.queue = asyncio.Queue(maxsize=100)
        self.forward_task = asyncio.create_task(self._forward_loop())

    def connection_made(self, transport):
        self.transport = transport
        asyncio.create_task(self._setup())

    def datagram_received(self, data, addr):
        try:
            self.queue.put_nowait((data, addr))
        except asyncio.QueueFull:
            pass

    async def _forward_loop(self):
        try:
            while True:
                data, addr = await self.queue.get()
                await self.forward_to_ws(data, addr)
                self.queue.task_done()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"UDP forward loop error: {e}")

    async def forward_to_ws(self, data, addr):
        try:
            # Pack source address + data
            packed_addr = pack_addr(addr[0], addr[1])
            # Packet: [SessionID 4B] + [Addr] + [Data]
            payload = struct.pack("!I", self.session_id) + packed_addr + data
            encrypted = self.cipher.encrypt(payload)
            await self.ws.send_bytes(encrypted)
        except Exception as e:
            logger.error(f"Failed to forward UDP Tunnel to WS: {e}")


async def proxy_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    password = request.app.get("password")
    cipher = Cipher(password)

    target_reader = None
    target_writer = None
    udp_transport = None

    try:
        # 1. Wait for handshake message
        msg = await ws.receive()

        handshake_data = None
        if msg.type == WSMsgType.BINARY:
            # Decrypt if needed
            try:
                decrypted = cipher.decrypt(msg.data)
                handshake_data = json.loads(decrypted)
            except Exception as e:
                logger.error(f"Handshake decryption failed: {e}")
                return ws
        elif msg.type == WSMsgType.TEXT:
            if password:
                logger.error("Received text handshake but password is required")
                return ws
            try:
                handshake_data = json.loads(msg.data)
            except Exception:
                pass

        if not handshake_data:
            logger.error("Invalid handshake")
            return ws

        cmd = handshake_data.get("cmd", "tcp_tunnel")

        async def send_json_response(data):
            json_bytes = json.dumps(data).encode("utf-8")
            encrypted = cipher.encrypt(json_bytes)
            await ws.send_bytes(encrypted)

        if cmd == "udp_tunnel":
            # Multiplexed UDP Tunnel
            logger.info("Starting UDP Tunnel Multiplexer")
            await send_json_response({"status": "ok"})

            sessions = {}  # session_id -> (transport, protocol)

            try:
                async for msg in ws:
                    if msg.type == WSMsgType.BINARY:
                        try:
                            decrypted = cipher.decrypt(msg.data)
                            if len(decrypted) < 4:
                                continue

                            sid = struct.unpack("!I", decrypted[:4])[0]
                            payload = decrypted[4:]

                            # Payload starts with SOCKS5 address
                            try:
                                # Use memoryview to avoid copies during unpacking
                                mv_payload = memoryview(payload)
                                host, port, consumed = unpack_addr(mv_payload)
                                data = mv_payload[consumed:]
                            except Exception as e:
                                logger.error(f"Address unpack error: {e}")
                                continue

                            if sid not in sessions:
                                loop = asyncio.get_running_loop()
                                (
                                    transport,
                                    protocol,
                                ) = await loop.create_datagram_endpoint(
                                    lambda: UDPTunnelProtocol(ws, cipher, sid),
                                    local_addr=("0.0.0.0", 0),
                                )
                                sessions[sid] = (transport, protocol)

                            transport, protocol = sessions[sid]
                            transport.sendto(data, (host, port))

                        except Exception as e:
                            logger.error(f"Tunnel error: {e}")
                    elif msg.type in (WSMsgType.CLOSED, WSMsgType.ERROR):
                        break
            finally:
                for transport, _ in sessions.values():
                    transport.close()
                sessions.clear()

        elif cmd == "tcp_tunnel":
            await send_json_response({"status": "ok"})
            sessions = {}

            async def target_to_ws(sid, reader):
                try:
                    while True:
                        data = await reader.read(16384)
                        if not data:
                            logger.info(f"Target connection closed for SID {sid}")
                            break
                        payload = struct.pack("!I", sid) + data
                        encrypted = cipher.encrypt(payload)
                        await ws.send_bytes(encrypted)
                except Exception as e:
                    logger.error(f"Error reading from target SID {sid}: {e}")
                finally:
                    # Notify client about closure
                    try:
                        resp = {"type": "close", "sid": sid}
                        b = json.dumps(resp).encode("utf-8")
                        await ws.send_bytes(cipher.encrypt(b))
                    except Exception:
                        pass

            try:
                async for msg in ws:
                    if msg.type == WSMsgType.BINARY:
                        try:
                            decrypted = cipher.decrypt(msg.data)
                            try:
                                obj = json.loads(decrypted)
                                t = obj.get("type")
                                if t == "open":
                                    sid = obj.get("sid")
                                    host = obj.get("host")
                                    port = obj.get("port")
                                    try:
                                        r, w = await asyncio.open_connection(host, port)
                                        # Enable TCP_NODELAY
                                        sock = w.get_extra_info("socket")
                                        if sock:
                                            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                                        
                                        task = asyncio.create_task(target_to_ws(sid, r))
                                        sessions[sid] = {
                                            "reader": r,
                                            "writer": w,
                                            "task": task,
                                        }
                                        resp = {
                                            "type": "open_ack",
                                            "sid": sid,
                                            "status": "ok",
                                        }
                                    except Exception as e:
                                        resp = {
                                            "type": "open_ack",
                                            "sid": sid,
                                            "status": "error",
                                            "message": str(e),
                                        }
                                    b = json.dumps(resp).encode("utf-8")
                                    await ws.send_bytes(cipher.encrypt(b))
                                elif t == "close":
                                    sid = obj.get("sid")
                                    s = sessions.pop(sid, None)
                                    if s:
                                        try:
                                            s["writer"].close()
                                        except Exception:
                                            pass
                                        try:
                                            await s["writer"].wait_closed()
                                        except Exception:
                                            pass
                            except Exception:
                                if len(decrypted) < 4:
                                    continue
                                sid = struct.unpack("!I", decrypted[:4])[0]
                                payload = decrypted[4:]
                                s = sessions.get(sid)
                                if s:
                                    try:
                                        s["writer"].write(payload)
                                        await s["writer"].drain()
                                    except Exception:
                                        pass
                        except Exception:
                            pass
                    elif msg.type in (WSMsgType.CLOSED, WSMsgType.ERROR):
                        break
            finally:
                for sid, s in sessions.items():
                    try:
                        s["writer"].close()
                        await s["writer"].wait_closed()
                    except Exception:
                        pass
                    task = s.get("task")
                    if task:
                        task.cancel()
                sessions.clear()

        else:
            await send_json_response({"status": "error", "message": "Unknown command"})
            return ws

    except Exception as e:
        logger.error(f"Proxy error: {e}")
    finally:
        if target_writer:
            target_writer.close()
            try:
                await target_writer.wait_closed()
            except Exception:
                pass
        if udp_transport:
            udp_transport.close()
        await ws.close()
        logger.info("Connection closed")

    return ws


def run_server(host="0.0.0.0", port=8080, password=None):
    app = web.Application()
    app["password"] = password
    app.router.add_get("/proxy", proxy_handler)
    logger.info(f"Starting server on {host}:{port}")
    if password:
        logger.info("Encryption enabled")
    web.run_app(app, host=host, port=port)


def main():
    if sys.platform != "win32":
        try:
            import uvloop
            uvloop.install()
            logger.info("uvloop installed")
        except ImportError:
            logger.warning("uvloop not installed, using default event loop")

    parser = argparse.ArgumentParser("wsproxy server")
    parser.add_argument(
        "--password", help="Encryption password (optional)", default=None
    )

    parser.add_argument(
        "--host", default="0.0.0.0", help="Host to bind (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", type=int, default=8080, help="Port to bind (default: 8080)"
    )

    args = parser.parse_args()
    run_server(host=args.host, port=args.port, password=args.password)


if __name__ == "__main__":
    main()
