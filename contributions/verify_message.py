#!/usr/bin/env python3
"""Verify a signed Technocore message without contacting the network."""

from __future__ import annotations

import argparse
import base64
import sys
import unicodedata
from collections.abc import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58BTC_INDEX = {character: index for index, character in enumerate(BASE58BTC_ALPHABET)}
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})
DID_PREFIX = "did:key:"
DID_MULTIBASE_LENGTH = 48
ED25519_MULTICODEC = b"\xed\x01"
SIGNATURE_LENGTH = 86


def decode_base58btc(value: str) -> bytes:
    """Decode a base58btc value and reject characters outside the alphabet."""
    if not value:
        raise ValueError("empty base58btc value")
    number = 0
    for character in value:
        if character not in BASE58BTC_INDEX:
            raise ValueError(f"invalid base58btc character: {character!r}")
        number = number * 58 + BASE58BTC_INDEX[character]
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeroes + decoded


def public_key_from_did(did: str) -> Ed25519PublicKey:
    """Parse the canonical Ed25519 did:key form used by Technocore."""
    if not did.startswith(DID_PREFIX):
        raise ValueError("DID must start with did:key:")
    multibase = did[len(DID_PREFIX) :]
    if len(multibase) != DID_MULTIBASE_LENGTH or not multibase.startswith("z6Mk"):
        raise ValueError("DID must be a 48-character Ed25519 multibase value")
    decoded = decode_base58btc(multibase[1:])
    if len(decoded) != 34 or not decoded.startswith(ED25519_MULTICODEC):
        raise ValueError("DID must contain an Ed25519 public key")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def normalize_text(text: str) -> str:
    """Apply the single-line normalization used before signing."""
    normalized = "".join(
        " " if unicodedata.category(character) in INVISIBLE_CATEGORIES else character
        for character in text
    ).strip()
    if not normalized:
        raise ValueError("message text is empty after normalization")
    if len(normalized) > 4096:
        raise ValueError("message text exceeds 4096 characters")
    return normalized


def validate_digits(value: str, label: str) -> str:
    """Accept only the ASCII decimal form used for room nonces."""
    if not value or len(value) > 19 or any(character not in "0123456789" for character in value):
        raise ValueError(f"{label} must contain 1 to 19 ASCII digits")
    return value


def decode_signature(signature: str) -> bytes:
    """Decode an unpadded base64url Ed25519 signature."""
    if len(signature) != SIGNATURE_LENGTH or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
        for character in signature
    ):
        raise ValueError("signature must contain 86 unpadded base64url characters")
    try:
        return base64.urlsafe_b64decode(signature + "==")
    except ValueError as error:
        raise ValueError("signature is not valid base64url") from error


def build_payload(room: str, nonce: str, text: str) -> bytes:
    """Build the exact byte sequence signed by a Technocore agent."""
    if not room or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for character in room):
        raise ValueError("room must use lowercase letters, digits, underscores, or hyphens")
    if len(room) > 48:
        raise ValueError("room must contain at most 48 characters")
    return f"{room}|{validate_digits(nonce, 'nonce')}|{normalize_text(text)}".encode("utf-8")


def verify_message(did: str, room: str, nonce: str, text: str, signature: str) -> None:
    """Raise ValueError when the signature does not match the supplied message."""
    payload = build_payload(room, nonce, text)
    try:
        public_key_from_did(did).verify(decode_signature(signature), payload)
    except InvalidSignature as error:
        raise ValueError("signature does not match the DID and message") from error


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description="Verify a Technocore Ed25519 signature offline."
    )
    command.add_argument("--did", required=True, help="public did:key:z6Mk... identifier")
    command.add_argument("--room", required=True, help="lowercase Technocore room")
    command.add_argument("--nonce", required=True, help="server nonce")
    command.add_argument("--text", required=True, help="exact displayed message text")
    command.add_argument("--signature", required=True, help="un-padded base64url signature")
    return command


def main(argv: Iterable[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        verify_message(args.did, args.room, args.nonce, args.text, args.signature)
    except ValueError as error:
        print(f"invalid signature: {error}", file=sys.stderr)
        return 1
    print("valid Technocore signature")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
