import asyncio
import logging
import json
import struct
import argparse
from aiohttp import web, WSMsgType
from wsproxy.utils import pack_addr, unpack_addr
from wsproxy.crypto import Cipher

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("server")


class UDPProxyProtocol(asyncio.DatagramProtocol):
    def __init__(self, ws, cipher):
        self.ws = ws
        self.cipher = cipher
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.create_task(self.forward_to_ws(data, addr))

    async def forward_to_ws(self, data, addr):
        try:
            # Pack source address + data
            packed_addr = pack_addr(addr[0], addr[1])
            payload = packed_addr + data
            encrypted = self.cipher.encrypt(payload)
            await self.ws.send_bytes(encrypted)
        except Exception as e:
            logger.error(f"Failed to forward UDP to WS: {e}")


class UDPTunnelProtocol(asyncio.DatagramProtocol):
    def __init__(self, ws, cipher, session_id):
        self.ws = ws
        self.cipher = cipher
        self.session_id = session_id
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.create_task(self.forward_to_ws(data, addr))

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

        cmd = handshake_data.get("cmd", "connect")

        async def send_json_response(data):
            json_bytes = json.dumps(data).encode("utf-8")
            encrypted = cipher.encrypt(json_bytes)
            await ws.send_bytes(encrypted)

        if cmd == "connect":
            target_host = handshake_data.get("host")
            target_port = handshake_data.get("port")

            if not target_host or not target_port:
                await send_json_response(
                    {"status": "error", "message": "Missing host or port"}
                )
                return ws

            logger.info(f"Connecting to {target_host}:{target_port}")
            try:
                target_reader, target_writer = await asyncio.open_connection(
                    target_host, target_port
                )
            except Exception as e:
                await send_json_response({"status": "error", "message": str(e)})
                return ws

            await send_json_response({"status": "ok"})

            # Pipe data for TCP
            async def ws_to_target():
                async for msg in ws:
                    if msg.type == WSMsgType.BINARY:
                        try:
                            decrypted = cipher.decrypt(msg.data)
                            target_writer.write(decrypted)
                            await target_writer.drain()
                        except Exception as e:
                            logger.error(f"Decryption error: {e}")
                            break
                    elif msg.type == WSMsgType.CLOSED or msg.type == WSMsgType.ERROR:
                        break

            async def target_to_ws():
                try:
                    while True:
                        data = await target_reader.read(4096)
                        if not data:
                            break
                        encrypted = cipher.encrypt(data)
                        await ws.send_bytes(encrypted)
                except Exception:
                    pass

            await asyncio.gather(ws_to_target(), target_to_ws())

        elif cmd == "udp":
            # Legacy Single UDP Mode
            logger.info("Starting UDP tunnel (Legacy)")
            loop = asyncio.get_running_loop()
            udp_transport, protocol = await loop.create_datagram_endpoint(
                lambda: UDPProxyProtocol(ws, cipher), local_addr=("0.0.0.0", 0)
            )
            await send_json_response({"status": "ok"})

            async for msg in ws:
                if msg.type == WSMsgType.BINARY:
                    try:
                        decrypted = cipher.decrypt(msg.data)
                        host, port, consumed = unpack_addr(decrypted)
                        payload = decrypted[consumed:]
                        udp_transport.sendto(payload, (host, port))
                    except Exception as e:
                        logger.error(f"UDP parsing/decryption error: {e}")
                elif msg.type == WSMsgType.CLOSED or msg.type == WSMsgType.ERROR:
                    break

        elif cmd == "udp_tunnel":
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
                                host, port, consumed = unpack_addr(payload)
                                data = payload[consumed:]
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
    parser = argparse.ArgumentParser(
        description="wsproxy: SOCKS5 over WebSocket Tunnel"
    )
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
