# 🚀 Sui MVR Provenance

# Build and Upload Move Bytecode

This GitHub Action builds a Move package using the Sui CLI and uploads the resulting `bytecode.dump.json` as an artifact.  
Useful for generating provenance data or integrating with MVR and downstream deployment workflows.

## 📥 Inputs

| Name                | Description                                                   | Required | Default |
| ------------------- | ------------------------------------------------------------- | -------- | ------- |
| `working-directory` | Path to the Move project directory (must contain `Move.toml`) | ✅ Yes   | `.`     |

## 📤 Output

Uploads a single artifact named `bytecode.dump.json`, containing base64-encoded compiled modules.

## 🛠 Example

```yaml
- name: Build and Upload Move Bytecode
  uses: zktx-io/sui-mvr-provenance@v0.0.0
  with:
    working-directory: ./my-move-package
```
