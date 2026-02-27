import asyncio
import logging
import json
import struct
import argparse
import socket
import sys
from aiohttp import web, WSMsgType
from wsproxy.utils import (
    pack_addr,
    unpack_addr,
    normalize_host,
    pack_tcp_frame,
    iter_tcp_frames,
    TCP_FRAME_OPEN,
    TCP_FRAME_OPEN_ACK,
    TCP_FRAME_DATA,
    TCP_FRAME_CLOSE,
)
from wsproxy.crypto import Cipher

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("server")

TCP_READ_CHUNK_SIZE = 65536
TCP_REMOTE_DRAIN_THRESHOLD = 64 * 1024
TCP_REMOTE_BUFFER_THRESHOLD = 128 * 1024
TCP_WS_CTRL_SEND_QUEUE_SIZE = 1024
TCP_WS_DATA_SEND_QUEUE_SIZE = 4096
TCP_WS_BATCH_MAX_FRAMES = 16
TCP_WS_BATCH_MAX_BYTES = 64 * 1024
TCP_WS_BATCH_WAIT_SECONDS = 0.001


class UDPTunnelProtocol(asyncio.DatagramProtocol):
    def __init__(self, ws, cipher, session_id):
        self.ws = ws
        self.cipher = cipher
        self.session_id = session_id
        self.transport = None
        self.queue = asyncio.Queue(maxsize=2048)
        self.forward_task = None

    def stop(self):
        if hasattr(self, "forward_task"):
            if self.forward_task:
                self.forward_task.cancel()
        if self.transport:
            self.transport.close()

    def connection_made(self, transport):
        self.transport = transport
        self.forward_task = asyncio.create_task(self._forward_loop())

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
    ws = web.WebSocketResponse(
        compress=False,
        max_msg_size=16 * 1024 * 1024,
        writer_limit=1 * 1024 * 1024,
    )
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
                for transport, protocol in sessions.values():
                    protocol.stop()
                sessions.clear()

        elif cmd == "tcp_tunnel":
            await send_json_response({"status": "ok"})
            sessions = {}
            ctrl_send_queue = asyncio.Queue(maxsize=TCP_WS_CTRL_SEND_QUEUE_SIZE)
            data_send_queue = asyncio.Queue(maxsize=TCP_WS_DATA_SEND_QUEUE_SIZE)

            def encode_open_ack(ok, message=""):
                if ok:
                    return b"\x00"
                msg = (message or "open session failed").encode("utf-8", errors="replace")
                if len(msg) > 1024:
                    msg = msg[:1024]
                return b"\x01" + msg

            def is_control_frame(frame_type):
                return frame_type in (TCP_FRAME_OPEN_ACK, TCP_FRAME_CLOSE)

            async def queue_frame(frame_type, sid, payload=b""):
                frame = pack_tcp_frame(frame_type, sid, payload)
                if is_control_frame(frame_type):
                    await ctrl_send_queue.put(frame)
                else:
                    await data_send_queue.put(frame)

            async def pop_next_outbound():
                try:
                    return "ctrl", ctrl_send_queue, ctrl_send_queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    return "data", data_send_queue, data_send_queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass

                get_ctrl = asyncio.create_task(ctrl_send_queue.get())
                get_data = asyncio.create_task(data_send_queue.get())
                done, pending = await asyncio.wait(
                    [get_ctrl, get_data], return_when=asyncio.FIRST_COMPLETED
                )
                for t in pending:
                    t.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)

                first = done.pop()
                if first is get_ctrl:
                    return "ctrl", ctrl_send_queue, first.result()
                return "data", data_send_queue, first.result()

            async def ws_sender_loop():
                loop = asyncio.get_running_loop()
                try:
                    while True:
                        queue_kind, queue_ref, first = await pop_next_outbound()
                        queue_ref.task_done()

                        if queue_kind == "ctrl":
                            await ws.send_bytes(cipher.encrypt(first))
                            continue

                        batch = [first]
                        total_bytes = len(first)
                        deadline = loop.time() + TCP_WS_BATCH_WAIT_SECONDS

                        while (
                            len(batch) < TCP_WS_BATCH_MAX_FRAMES
                            and total_bytes < TCP_WS_BATCH_MAX_BYTES
                        ):
                            if not ctrl_send_queue.empty():
                                break
                            timeout = deadline - loop.time()
                            if timeout <= 0:
                                break
                            try:
                                frame = await asyncio.wait_for(data_send_queue.get(), timeout=timeout)
                            except asyncio.TimeoutError:
                                break
                            data_send_queue.task_done()
                            batch.append(frame)
                            total_bytes += len(frame)

                        merged = b"".join(batch)
                        await ws.send_bytes(cipher.encrypt(merged))
                except asyncio.CancelledError:
                    pass
                except Exception as e:
                    logger.error(f"TCP sender loop error: {e}")

            async def close_target_session(sid, notify_client=False):
                s = sessions.pop(sid, None)
                if not s:
                    return
                task = s.get("task")
                current = asyncio.current_task()
                if task and task is not current:
                    task.cancel()
                writer = s.get("writer")
                if writer:
                    try:
                        writer.close()
                    except Exception:
                        pass
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                if notify_client:
                    try:
                        await queue_frame(TCP_FRAME_CLOSE, sid)
                    except Exception:
                        pass

            async def target_to_ws(sid, reader):
                try:
                    while True:
                        data = await reader.read(TCP_READ_CHUNK_SIZE)
                        if not data:
                            break
                        await queue_frame(TCP_FRAME_DATA, sid, data)
                except Exception as e:
                    logger.error(f"Error reading from target SID {sid}: {e}")
                finally:
                    await close_target_session(sid, notify_client=True)

            sender_task = asyncio.create_task(ws_sender_loop())
            try:
                async for msg in ws:
                    if msg.type == WSMsgType.BINARY:
                        try:
                            decrypted = cipher.decrypt(msg.data)
                            for frame_type, sid, payload in iter_tcp_frames(decrypted):
                                if frame_type == TCP_FRAME_OPEN:
                                    try:
                                        host, port, consumed = unpack_addr(payload)
                                        if consumed != len(payload):
                                            raise ValueError("invalid OPEN payload length")

                                        normalized_host = normalize_host(host)
                                        r, w = await asyncio.wait_for(
                                            asyncio.open_connection(normalized_host, port),
                                            timeout=10,
                                        )
                                        sock = w.get_extra_info("socket")
                                        if sock:
                                            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                                        task = asyncio.create_task(target_to_ws(sid, r))
                                        sessions[sid] = {
                                            "reader": r,
                                            "writer": w,
                                            "task": task,
                                            "drain_pending": 0,
                                        }
                                        await queue_frame(TCP_FRAME_OPEN_ACK, sid, encode_open_ack(True))
                                    except Exception as e:
                                        await queue_frame(
                                            TCP_FRAME_OPEN_ACK,
                                            sid,
                                            encode_open_ack(False, f"server: {str(e)}"),
                                        )
                                elif frame_type == TCP_FRAME_DATA:
                                    s = sessions.get(sid)
                                    if not s:
                                        continue
                                    writer = s.get("writer")
                                    if not writer:
                                        continue
                                    try:
                                        writer.write(payload)
                                        pending = s.get("drain_pending", 0) + len(payload)
                                        transport = getattr(writer, "transport", None)
                                        if pending >= TCP_REMOTE_DRAIN_THRESHOLD or (
                                            transport
                                            and transport.get_write_buffer_size() >= TCP_REMOTE_BUFFER_THRESHOLD
                                        ):
                                            await writer.drain()
                                            pending = 0
                                        s["drain_pending"] = pending
                                    except Exception:
                                        await close_target_session(sid)
                                elif frame_type == TCP_FRAME_CLOSE:
                                    await close_target_session(sid)
                        except Exception as e:
                            logger.error(f"TCP tunnel frame error: {e}")
                    elif msg.type in (WSMsgType.CLOSED, WSMsgType.ERROR):
                        break
            finally:
                sender_task.cancel()
                await asyncio.gather(sender_task, return_exceptions=True)
                for sid in list(sessions.keys()):
                    await close_target_session(sid)
                sessions.clear()

        else:
            await send_json_response({"status": "error", "message": "server: Unknown command"})
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
