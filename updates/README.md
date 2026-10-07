# AEGIS update manifests

Do not place the private release-signing key in this repository.

Live channel files will be:
- `stable.json`
- `stable.json.sig`
- `beta.json`
- `beta.json.sig`

The `.sig` file is a detached Ed25519 signature over the exact bytes of the corresponding JSON file.

Clients must:
1. download JSON and signature through AEGIS Tor;
2. verify the Ed25519 signature using the public release key embedded in the client;
3. parse the JSON only after successful signature verification;
4. reject downgrades;
5. download the platform artifact;
6. verify file size and SHA-256 before installation.

Do not publish unsigned live manifests.
