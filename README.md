# AEGIS Releases

Official binary releases and signed update manifests for AEGIS.

This repository is intended for distribution only. It must never contain:
- private release-signing keys;
- account passwords;
- letter passwords or FF1 codes;
- private identity keys;
- Tor onion-service private keys;
- production database backups.

## Update channels

Signed manifests will live under `updates/`:
- `updates/stable.json` + `updates/stable.json.sig`
- `updates/beta.json` + `updates/beta.json.sig`

Release binaries will be published as GitHub Release assets.

The AEGIS clients must verify the embedded Ed25519 release public key before trusting any update manifest.
