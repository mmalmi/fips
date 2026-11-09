import hashlib
import runpy
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


merchant = runpy.run_path(str(Path(__file__).with_name("freedom-merchant")))
redeem = merchant["redeem"]


class PaymentRecovery(unittest.TestCase):
    def test_recovery_matches_original_inputs_and_rejects_reassignment(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            config = base / "merchant.toml"
            database = base / "wallet.sqlite"
            mint = "https://mint.example"
            seed = hashlib.sha256(b"test proof identifier").hexdigest()
            y = merchant["proof_y"](bytes.fromhex(seed))
            order = dict(order="a"*40, mint=mint, amount=10, seeds=[seed], token="test-token")
            with sqlite3.connect(database) as db:
                db.execute("CREATE TABLE transactions (ys BLOB, direction, status, mint_url, unit, amount, payment_method)")
            def wallet(_config, action, _args, _token):
                if action == "inspect":
                    return {"token_preview": {"mint_url": mint, "unit": "sat"}}
                with sqlite3.connect(database) as db:
                    db.execute("INSERT INTO transactions VALUES (?, 'Incoming', 'completed', ?, 'sat', 10, NULL)", (y, mint))
                raise ValueError("lost reply")
            with patch.dict("os.environ", FREEDOM_WALLET_DB=str(database)), patch.dict(redeem.__globals__, wallet=wallet):
                self.assertEqual(redeem(config, order)["received"]["amount_sat"], 10)
                recovery = dict(order, token="")
                self.assertEqual(redeem(config, recovery)["received"]["amount_sat"], 10)
                for changed in (dict(recovery, order="b"*40), dict(recovery, amount=12)):
                    with self.assertRaises(ValueError):
                        redeem(config, changed)
                with sqlite3.connect(database) as db:
                    self.assertEqual(db.execute("SELECT count(*) FROM transactions").fetchone(), (1,))


if __name__ == "__main__":
    unittest.main()
