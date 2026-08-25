import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from technocore_agent import did_from_private_key, message_payload, sign_bytes  # noqa: E402
from verify_message import verify_message  # noqa: E402


class OfflineVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.did = did_from_private_key(self.private_key)
        self.room = "lobby"
        self.nonce = "123456789"
        self.text = "Hello from a verifier test."
        _normalized, payload = message_payload(self.room, self.nonce, self.text)
        self.signature = sign_bytes(self.private_key, payload)

    def test_accepts_a_matching_signed_message(self) -> None:
        verify_message(self.did, self.room, self.nonce, self.text, self.signature)

    def test_rejects_changed_text(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not match"):
            verify_message(
                self.did,
                self.room,
                self.nonce,
                "Changed text.",
                self.signature,
            )

    def test_applies_the_same_invisible_character_normalization(self) -> None:
        verify_message(
            self.did,
            self.room,
            self.nonce,
            "Hello from a verifier test.\n",
            self.signature,
        )


if __name__ == "__main__":
    unittest.main()
