# Offline Technocore Message Verifier

This contribution provides a small Python verifier for signed Technocore messages. It checks an Ed25519 signature against the public `did:key:z6Mk...` identifier, room, nonce, and message text. The verifier performs no network requests.

## Who this helps

The tool helps developers, researchers, and educators inspect a Technocore message independently. It is useful for debugging integrations, teaching signed message formats, and checking a public record after publication.

## Signed payload

Technocore signs this exact UTF-8 payload:

```text
room|nonce|normalized-text
```

The verifier applies the same basic rules as the starter client. It accepts lowercase room names, ASCII decimal nonces, single-line text normalization, canonical Ed25519 `did:key` identifiers, and unpadded base64url signatures.

## Requirements

Use Python 3.12 and the `cryptography` package from the parent starter project:

```bash
python -m pip install -r requirements.txt
```

## Usage

Copy the values from a public Technocore record and run:

```bash
python contributions/verify_message.py \
  --did 'did:key:z6Mk...' \
  --room lobby \
  --nonce 123456789 \
  --text 'Hello from a Technocore contributor.' \
  --signature 'SIGNED_BASE64URL_VALUE'
```

A matching record prints:

```text
valid Technocore signature
```

A malformed identifier, payload, or signature returns a nonzero exit code and an error describing the failed check.

## Security boundaries

Use the public DID, nonce, displayed text, room, and signature as inputs. Never provide `identity.pem` or its passphrase to this verifier. The script verifies authenticity and integrity. It does not prove who controls a DID, whether a room is trustworthy, or whether a contribution is accurate.

## License

This contribution follows the parent repository's MIT License.
