# 🚀 Sui MVR Provenance

# Build and Upload Move Bytecode

This GitHub Action builds a Move package using the Sui CLI and uploads the resulting `bytecode.dump.json` as an artifact.  
Useful for generating provenance data or integrating with MVR and downstream deployment workflows.

## 📥 Inputs

| Name                | Description                                                   | Required | Default |
| ------------------- | ------------------------------------------------------------- | -------- | ------- |
| `working-directory` | Path to the Move project directory (must contain `Move.toml`) | ✅ Yes   | `.`     |

## 📄 Required: `mvr.config.json`

The `working-directory` must include a `mvr.config.json` file to define deployment metadata for MVR.

```json
{
  "network": "mainnet",
  "owner": "0x123...abc",
  "package_name": "example_package",
  "package_id": "0xabc...def",
  "upgrade_cap_id": "0xabc...def"
}
```

- `network` _(string)_: The Sui network to deploy to. One of "mainnet", "testnet", or "devnet".
- `owner` _(string)_: The address used to deploy the package. Must be authorized to sign.
- `package_name` _(string, optional)_: Used for MVR registration.
- `package_id` _(string, optional)_: The ID of the existing package. Required for MVR registration or upgrade tracking.
- `upgrade_cap_id` _(string, optional)_: If present, triggers an upgrade instead of a fresh deploy.

This config file will be used during deployment and provenance generation.

## 🔧 Behavior

- If package_name is not provided, only deployment will be executed — MVR registration will be skipped.
- If address is provided, the transaction will be treated as an upgrade.
- network and gas_budget are required.
- The config file must exist at ${{ inputs.working-directory }}/mvr.config.json.

## 📤 Output

Uploads a single artifact named `bytecode.dump.json`, containing base64-encoded compiled modules.

## 🛠 Example

```yaml
- name: Build and Upload Move Bytecode
  uses: zktx-io/sui-mvr-provenance@v0.0.7
  with:
    working-directory: ./my-move-package
```
