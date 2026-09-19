# Universal iPod Firmware Decryptor v3.2.3

Documentation correction for the Nano 5G decryption path.

## Nano 5G status

The Nano 5G S5L8730 hardware-AES process has successfully produced coherent decrypted OSOS firmware for RetailOS 1.0.1 and 1.0.2.

Validated outputs:

```text
OSOS 1.0.1
size:   7,276,688 bytes
SHA256: EA4BAD8DC8C8C57EA3144F9615B92D6865AB34BEC267229B41E7B12CF6B491F4

OSOS 1.0.2
size:   7,286,720 bytes
SHA256: 3269D9EDA2E7E7C406D7BFD6895BD83F27603F03A2C9F52C6CF415924E41AF81
```

Both outputs validate as S5L8730 IMG1 format-4 images with consistent lengths, aligned bodies, valid unsigned-image placeholders, and expected RetailOS anchors.

## Scope

- Documentation only; the executable binary is unchanged.
- Use `DECRYPTION_METHODS.md` for the per-model method matrix.
- Use `BUILD.md` for source builds and external dependencies.
- The executable remains a release asset and is not committed to Git.
