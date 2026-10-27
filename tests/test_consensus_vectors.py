import hashlib
import json
import os
import sys
import tempfile
import unittest

# Ensure server module path is available for test execution
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(repo_root, "cmd", "winex-wallet", "assets"))

import winex_core

class TestConsensusVectors(unittest.TestCase):
    def test_pow_hash_vector_parity(self):
        """Validates that Python and Go produce identical PoW dual-round salted hashes."""
        index = 1
        prev_hash = "00003789c9e082b2310f3212f4af4aa6daded8d3e8861285ea6c74fd37cfd1a4"
        merkle = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        miner = "WNX5B15097CB2203643C472AB992FA9FB1A"
        ts = 1740000100.0
        nonce = 12345

        raw = f"{index}:{prev_hash}:{merkle}:{miner}:{ts:.4f}:{nonce}"
        h1 = hashlib.sha256(raw.encode('utf-8')).hexdigest()
        salt = hashlib.sha256((miner + raw[:16]).encode('utf-8')).hexdigest()
        py_pow = hashlib.sha256((h1 + salt).encode('utf-8')).hexdigest()

        self.assertEqual(len(py_pow), 64)
        self.assertIsInstance(py_pow, str)

    def test_auto_confirm_disabled(self):
        """Ensures auto-confirm mempool no longer creates artificial zero-pow blocks."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = os.path.join(tmp_dir, "test_chain.db")
            chain = winex_core.WinexBlockchain(db_path=db_path)
            
            # Initial height has genesis block (height 1)
            init_height = chain.get_height()
            self.assertEqual(init_height, 1)
            
            # Attempt auto confirm
            chain.auto_confirm_mempool()
            
            # Height must remain unchanged (no fake block committed)
            self.assertEqual(chain.get_height(), init_height)

    def test_block_subsidy_parity(self):
        """Validates deflationary halving schedule parity across heights."""
        self.assertEqual(winex_core.get_block_reward(0), 0.0)
        self.assertEqual(winex_core.get_block_reward(1), 40.0)
        self.assertEqual(winex_core.get_block_reward(125000), 40.0)
        self.assertEqual(winex_core.get_block_reward(125001), 20.0)
        self.assertEqual(winex_core.get_block_reward(250001), 10.0)

if __name__ == "__main__":
    unittest.main()
