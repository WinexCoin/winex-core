import asyncio
import os
import sys
import unittest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(repo_root, "server"))

import winex_stratum

class MockReader:
    def __init__(self, data: bytes, chunk_size: int = 128):
        self._data = data
        self._chunk_size = chunk_size
        self._pos = 0

    async def read(self, n: int = -1) -> bytes:
        if self._pos >= len(self._data):
            return b""
        read_n = min(self._chunk_size, len(self._data) - self._pos)
        chunk = self._data[self._pos:self._pos + read_n]
        self._pos += read_n
        return chunk

class MockWriter:
    def __init__(self):
        self.closed = False
        self.written = []

    def write(self, data: bytes):
        self.written.append(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass

class TestStratumFraming(unittest.IsolatedAsyncioTestCase):
    async def test_pipelined_frames(self):
        """Validates that pipelined frames in a single chunk are both received."""
        payload = b'{"method":"mining.subscribe","id":1}\n{"method":"mining.authorize","id":2}\n'
        reader = MockReader(payload, chunk_size=256)
        writer = MockWriter()
        client = winex_stratum.StratumClient(reader, writer, "127.0.0.1")

        line1 = await client.read_line_bounded()
        self.assertEqual(line1, b'{"method":"mining.subscribe","id":1}')

        line2 = await client.read_line_bounded()
        self.assertEqual(line2, b'{"method":"mining.authorize","id":2}')

        line3 = await client.read_line_bounded()
        self.assertIsNone(line3)

    async def test_oversized_frame_rejected(self):
        """Oversized frames exceeding MAX_FRAME_SIZE (4096) must be dropped."""
        payload = b"A" * 5000 + b"\n"
        reader = MockReader(payload, chunk_size=128)
        writer = MockWriter()
        client = winex_stratum.StratumClient(reader, writer, "127.0.0.1")

        line = await client.read_line_bounded()
        self.assertIsNone(line)

    async def test_eof_without_newline(self):
        """Buffer left over at EOF must be returned as final line."""
        payload = b'{"method":"mining.ping"}'
        reader = MockReader(payload, chunk_size=128)
        writer = MockWriter()
        client = winex_stratum.StratumClient(reader, writer, "127.0.0.1")

        line = await client.read_line_bounded()
        self.assertEqual(line, b'{"method":"mining.ping"}')

if __name__ == "__main__":
    unittest.main()
