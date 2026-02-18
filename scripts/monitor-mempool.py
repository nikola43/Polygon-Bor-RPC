#!/usr/bin/env python3
"""
Polygon Bor Mempool Monitor
Subscribes to pending transactions via WebSocket and polls txpool status.
No external dependencies beyond Python 3.7+ standard library.
"""

import asyncio
import json
import time
import sys
import signal
from collections import deque

# --- Configuration ---
WS_URL = "ws://127.0.0.1:8546"
HTTP_URL = "http://127.0.0.1:8545"
TXPOOL_POLL_INTERVAL = 15  # seconds
RATE_WINDOW = 10  # seconds for rolling tx rate

# --- Globals ---
tx_timestamps = deque()
total_tx_count = 0
start_time = None
running = True


def signal_handler(sig, frame):
    global running
    print("\n\nShutting down...")
    running = False


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def calc_tx_rate():
    """Calculate transactions per second over the rolling window."""
    now = time.time()
    # Remove timestamps outside the window
    while tx_timestamps and tx_timestamps[0] < now - RATE_WINDOW:
        tx_timestamps.popleft()
    if not tx_timestamps:
        return 0.0
    return len(tx_timestamps) / RATE_WINDOW


async def poll_txpool_status():
    """Periodically poll txpool_status via HTTP JSON-RPC."""
    import urllib.request

    while running:
        try:
            payload = json.dumps({
                "jsonrpc": "2.0",
                "method": "txpool_status",
                "params": [],
                "id": 1
            }).encode()
            req = urllib.request.Request(
                HTTP_URL,
                data=payload,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                result = data.get("result", {})
                pending = int(result.get("pending", "0x0"), 16)
                queued = int(result.get("queued", "0x0"), 16)
                rate = calc_tx_rate()
                elapsed = time.time() - start_time if start_time else 0

                print(
                    f"\r[txpool] pending={pending:,}  queued={queued:,}  "
                    f"| rate={rate:.1f} tx/s  "
                    f"| total={total_tx_count:,}  "
                    f"| uptime={int(elapsed)}s",
                    end="", flush=True
                )
        except Exception as e:
            print(f"\r[txpool] poll error: {e}", end="", flush=True)

        await asyncio.sleep(TXPOOL_POLL_INTERVAL)


async def subscribe_pending_txs():
    """Subscribe to newPendingTransactions via WebSocket."""
    global total_tx_count, start_time

    # Import websockets-like functionality using only stdlib
    # We'll use a raw WebSocket implementation
    import hashlib
    import base64
    import struct
    import os
    from urllib.parse import urlparse

    parsed = urlparse(WS_URL)
    host = parsed.hostname
    port = parsed.port or 8546

    while running:
        reader = None
        writer = None
        try:
            print(f"Connecting to {WS_URL} ...")
            reader, writer = await asyncio.open_connection(host, port)

            # WebSocket handshake
            ws_key = base64.b64encode(os.urandom(16)).decode()
            handshake = (
                f"GET {parsed.path or '/'} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"\r\n"
            )
            writer.write(handshake.encode())
            await writer.drain()

            # Read handshake response
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=10)
                if not chunk:
                    raise ConnectionError("Connection closed during handshake")
                response += chunk

            if b"101" not in response.split(b"\r\n")[0]:
                raise ConnectionError(f"WebSocket handshake failed: {response[:200]}")

            print("Connected! Subscribing to newPendingTransactions...")

            # Send subscription request
            sub_msg = json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_subscribe",
                "params": ["newPendingTransactions"]
            })
            await ws_send(writer, sub_msg)

            # Read subscription confirmation
            msg = await ws_recv(reader)
            sub_data = json.loads(msg)
            if "result" in sub_data:
                print(f"Subscribed! Subscription ID: {sub_data['result']}")
            else:
                print(f"Subscription response: {msg[:200]}")

            start_time = time.time()
            print("Listening for pending transactions...\n")

            # Listen for pending tx notifications
            while running:
                msg = await asyncio.wait_for(ws_recv(reader), timeout=60)
                data = json.loads(msg)

                if "params" in data:
                    tx_hash = data["params"].get("result", "")
                    now = time.time()
                    tx_timestamps.append(now)
                    total_tx_count += 1

                    rate = calc_tx_rate()
                    if total_tx_count % 100 == 0:
                        elapsed = now - start_time
                        print(
                            f"\r[stream] tx #{total_tx_count:,}  "
                            f"hash={tx_hash[:18]}...  "
                            f"rate={rate:.1f} tx/s  "
                            f"uptime={int(elapsed)}s     ",
                            end="", flush=True
                        )

        except asyncio.TimeoutError:
            print("\nWebSocket timeout, reconnecting...")
        except (ConnectionError, OSError) as e:
            print(f"\nConnection error: {e}")
        except Exception as e:
            print(f"\nUnexpected error: {e}")
        finally:
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        if running:
            print("Reconnecting in 3 seconds...")
            await asyncio.sleep(3)


async def ws_send(writer, message):
    """Send a WebSocket text frame."""
    import os
    payload = message.encode("utf-8")
    mask_key = os.urandom(4)

    # Build frame header
    header = bytearray()
    header.append(0x81)  # FIN + text opcode

    length = len(payload)
    if length < 126:
        header.append(0x80 | length)  # Masked
    elif length < 65536:
        header.append(0x80 | 126)
        header.extend(length.to_bytes(2, "big"))
    else:
        header.append(0x80 | 127)
        header.extend(length.to_bytes(8, "big"))

    header.extend(mask_key)

    # Mask payload
    masked = bytearray(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    writer.write(bytes(header) + bytes(masked))
    await writer.drain()


async def ws_recv(reader):
    """Receive a WebSocket text frame."""
    # Read first 2 bytes
    data = await reader.readexactly(2)
    opcode = data[0] & 0x0F
    masked = bool(data[1] & 0x80)
    length = data[1] & 0x7F

    if length == 126:
        data = await reader.readexactly(2)
        length = int.from_bytes(data, "big")
    elif length == 127:
        data = await reader.readexactly(8)
        length = int.from_bytes(data, "big")

    if masked:
        mask_key = await reader.readexactly(4)

    payload = await reader.readexactly(length)

    if masked:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

    if opcode == 0x8:  # Close
        raise ConnectionError("WebSocket closed by server")
    if opcode == 0x9:  # Ping - send pong
        return await ws_recv(reader)  # Skip and read next

    return payload.decode("utf-8")


async def main():
    print("=" * 60)
    print("  Polygon Bor Mempool Monitor")
    print("=" * 60)
    print(f"  WebSocket: {WS_URL}")
    print(f"  HTTP RPC:  {HTTP_URL}")
    print(f"  Rate window: {RATE_WINDOW}s")
    print(f"  txpool poll: every {TXPOOL_POLL_INTERVAL}s")
    print("=" * 60)
    print()

    # Run both tasks concurrently
    await asyncio.gather(
        subscribe_pending_txs(),
        poll_txpool_status()
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nBye!")
        sys.exit(0)
