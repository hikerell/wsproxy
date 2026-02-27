#!/usr/bin/env python3
import argparse
import asyncio
import ipaddress
import os
import random
import socket
import statistics
import struct
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class WorkerStats:
    connect_ok: int = 0
    connect_fail: int = 0
    requests_ok: int = 0
    requests_fail: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    latencies_ms_sample: Optional[List[float]] = None


class Reservoir:
    def __init__(self, max_samples: int):
        self.max_samples = max_samples
        self.samples: List[float] = []
        self.seen = 0

    def add(self, value: float) -> None:
        self.seen += 1
        if len(self.samples) < self.max_samples:
            self.samples.append(value)
            return
        idx = random.randint(0, self.seen - 1)
        if idx < self.max_samples:
            self.samples[idx] = value


def percentile(sorted_values: List[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    pos = (len(sorted_values) - 1) * p
    lo = int(pos)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = pos - lo
    return sorted_values[lo] * (1.0 - frac) + sorted_values[hi] * frac


def build_socks_addr(host: str, port: int) -> bytes:
    try:
        v4 = ipaddress.IPv4Address(host)
        return b"\x01" + v4.packed + struct.pack("!H", port)
    except ipaddress.AddressValueError:
        pass

    try:
        v6 = ipaddress.IPv6Address(host)
        return b"\x04" + v6.packed + struct.pack("!H", port)
    except ipaddress.AddressValueError:
        pass

    b = host.encode("utf-8")
    if len(b) > 255:
        raise ValueError("domain too long")
    return b"\x03" + bytes([len(b)]) + b + struct.pack("!H", port)


async def open_socks5_tunnel(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    timeout: float,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(socks_host, socks_port), timeout=timeout
    )

    writer.write(b"\x05\x01\x00")
    await asyncio.wait_for(writer.drain(), timeout=timeout)
    resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
    if resp != b"\x05\x00":
        writer.close()
        await writer.wait_closed()
        raise RuntimeError(f"SOCKS5 auth negotiation failed: {resp.hex()}")

    req = b"\x05\x01\x00" + build_socks_addr(target_host, target_port)
    writer.write(req)
    await asyncio.wait_for(writer.drain(), timeout=timeout)

    head = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
    if head[0] != 0x05:
        writer.close()
        await writer.wait_closed()
        raise RuntimeError("Invalid SOCKS5 version in CONNECT response")
    if head[1] != 0x00:
        writer.close()
        await writer.wait_closed()
        raise RuntimeError(f"SOCKS5 CONNECT failed, REP=0x{head[1]:02x}")

    atyp = head[3]
    if atyp == 0x01:
        await asyncio.wait_for(reader.readexactly(4 + 2), timeout=timeout)
    elif atyp == 0x03:
        n = await asyncio.wait_for(reader.readexactly(1), timeout=timeout)
        await asyncio.wait_for(reader.readexactly(n[0] + 2), timeout=timeout)
    elif atyp == 0x04:
        await asyncio.wait_for(reader.readexactly(16 + 2), timeout=timeout)
    else:
        writer.close()
        await writer.wait_closed()
        raise RuntimeError(f"Unknown BND ATYP: {atyp}")

    return reader, writer


async def echo_handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            hdr = await reader.readexactly(4)
            n = struct.unpack("!I", hdr)[0]
            if n == 0:
                continue
            payload = await reader.readexactly(n)
            writer.write(hdr)
            writer.write(payload)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def run_echo_server(host: str, port: int) -> None:
    server = await asyncio.start_server(echo_handle_client, host, port)
    for sock in server.sockets or []:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    print(f"echo-server listening on {host}:{port} (frame: 4-byte length + payload)")
    async with server:
        await server.serve_forever()


async def worker_loop(worker_id: int, args: argparse.Namespace, stop_at: float) -> WorkerStats:
    stats = WorkerStats(latencies_ms_sample=[])
    reservoir = Reservoir(args.max_latency_samples_per_worker)
    payload = os.urandom(args.payload_size)

    try:
        reader, writer = await open_socks5_tunnel(
            args.socks_host,
            args.socks_port,
            args.target_host,
            args.target_port,
            args.connect_timeout,
        )
        stats.connect_ok += 1
    except Exception:
        stats.connect_fail += 1
        return stats

    try:
        while time.perf_counter() < stop_at:
            t0 = time.perf_counter_ns()
            try:
                if args.mode == "echo":
                    frame = struct.pack("!I", len(payload)) + payload
                    writer.write(frame)
                    await asyncio.wait_for(writer.drain(), timeout=args.io_timeout)
                    rh = await asyncio.wait_for(reader.readexactly(4), timeout=args.io_timeout)
                    rn = struct.unpack("!I", rh)[0]
                    data = await asyncio.wait_for(reader.readexactly(rn), timeout=args.io_timeout)
                    if args.verify_echo and (rn != len(payload) or data != payload):
                        raise RuntimeError("echo payload mismatch")
                    stats.bytes_sent += len(frame)
                    stats.bytes_recv += len(rh) + len(data)
                else:
                    writer.write(payload)
                    await asyncio.wait_for(writer.drain(), timeout=args.io_timeout)
                    stats.bytes_sent += len(payload)

                t1 = time.perf_counter_ns()
                reservoir.add((t1 - t0) / 1_000_000.0)
                stats.requests_ok += 1
            except Exception:
                stats.requests_fail += 1
                if args.mode == "echo":
                    break

            if args.requests_per_connection > 0 and stats.requests_ok >= args.requests_per_connection:
                break
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    stats.latencies_ms_sample = reservoir.samples
    return stats


def format_rate(num: float) -> str:
    mib = num / (1024 * 1024)
    return f"{mib:.2f} MiB/s"


async def run_tcp_bench(args: argparse.Namespace) -> None:
    if args.mode == "sendonly" and args.verify_echo:
        raise ValueError("--verify-echo only works with --mode echo")

    started = time.perf_counter()
    stop_at = started + args.duration

    tasks = [asyncio.create_task(worker_loop(i, args, stop_at)) for i in range(args.connections)]
    all_stats = await asyncio.gather(*tasks)

    ended = time.perf_counter()
    elapsed = max(ended - started, 1e-6)

    connect_ok = sum(s.connect_ok for s in all_stats)
    connect_fail = sum(s.connect_fail for s in all_stats)
    req_ok = sum(s.requests_ok for s in all_stats)
    req_fail = sum(s.requests_fail for s in all_stats)
    sent = sum(s.bytes_sent for s in all_stats)
    recv = sum(s.bytes_recv for s in all_stats)

    lat_samples: List[float] = []
    for s in all_stats:
        if s.latencies_ms_sample:
            lat_samples.extend(s.latencies_ms_sample)

    print("=== wsproxy tcp bench result ===")
    print(f"mode: {args.mode}")
    print(f"socks5: {args.socks_host}:{args.socks_port}")
    print(f"target: {args.target_host}:{args.target_port}")
    print(f"connections: {args.connections}")
    print(f"duration: {elapsed:.2f}s")
    print(f"connect_ok/connect_fail: {connect_ok}/{connect_fail}")
    print(f"requests_ok/requests_fail: {req_ok}/{req_fail}")
    print(f"sent: {sent} bytes ({format_rate(sent / elapsed)})")
    print(f"recv: {recv} bytes ({format_rate(recv / elapsed)})")
    if elapsed > 0:
        print(f"req_rate: {req_ok / elapsed:.2f} req/s")

    if lat_samples:
        lat_samples.sort()
        p50 = percentile(lat_samples, 0.50)
        p95 = percentile(lat_samples, 0.95)
        p99 = percentile(lat_samples, 0.99)
        avg = statistics.fmean(lat_samples)
        print(
            f"latency_ms(sampled): avg={avg:.2f} p50={p50:.2f} p95={p95:.2f} p99={p99:.2f} "
            f"samples={len(lat_samples)}"
        )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Benchmark wsproxy via local SOCKS5 endpoint")
    sub = p.add_subparsers(dest="cmd", required=True)

    echo = sub.add_parser("echo-server", help="run a simple length-prefixed TCP echo server")
    echo.add_argument("--host", default="0.0.0.0")
    echo.add_argument("--port", type=int, default=19090)

    bench = sub.add_parser("tcp-bench", help="benchmark TCP tunnel through SOCKS5")
    bench.add_argument("--socks-host", default="127.0.0.1")
    bench.add_argument("--socks-port", type=int, default=1080)
    bench.add_argument("--target-host", required=True)
    bench.add_argument("--target-port", type=int, required=True)
    bench.add_argument("--connections", type=int, default=64)
    bench.add_argument("--duration", type=int, default=20)
    bench.add_argument("--payload-size", type=int, default=1024)
    bench.add_argument("--mode", choices=["echo", "sendonly"], default="echo")
    bench.add_argument("--verify-echo", action="store_true")
    bench.add_argument("--connect-timeout", type=float, default=8.0)
    bench.add_argument("--io-timeout", type=float, default=8.0)
    bench.add_argument("--requests-per-connection", type=int, default=0)
    bench.add_argument("--max-latency-samples-per-worker", type=int, default=4000)

    return p


async def async_main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.cmd == "echo-server":
        await run_echo_server(args.host, args.port)
        return
    if args.cmd == "tcp-bench":
        await run_tcp_bench(args)
        return

    raise RuntimeError(f"unknown command: {args.cmd}")


def main() -> None:
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
