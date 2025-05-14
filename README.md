# 🚀 Sui MVR Provenance

> **V now stands for _Verifiability_** — not just a registry, but a **trust layer** for Move packages.
> With provenance support powered by CI/CD, this project transforms the Move Registry into something you can **verify**, not just use.

### 🔍 What is this?

This GitHub Action builds a Move package using the Sui CLI, generates provenance metadata, and registers it in the [Move Registry (MVR)](https://www.moveregistry.com/).

Every deployment includes:

- A compiled `bytecode.dump.json`
- An `intoto.jsonl` SLSA provenance bundle
- Metadata registration to MVR via `mvr.config.json`

### ⚙️ Quick Start

```yaml
- name: Build and Upload Move Smart Contract
  uses: zktx-io/sui-mvr-provenance@v0.2.0
  with:
    working-directory: my-move-package
  env:
    ED25519_PRIVATE_KEY: ${{ secrets.ED25519_PRIVATE_KEY }}
    GIT_SIGNER_PIN: ${{ secrets.GIT_SIGNER_PIN }} # optional
```

> ⚠️ The `mvr.config.json` file must exist in your working directory.

### 🔐 Environment Variables

| Variable              | Required | Description                                                                          |
| --------------------- | -------- | ------------------------------------------------------------------------------------ |
| `ED25519_PRIVATE_KEY` | ✅       | Default signing key in Sui format (`suiprivkey...`)                                  |
| `GIT_SIGNER_PIN`      | optional | Enables secure remote signing via [notary.wal.app/sign](https://notary.wal.app/sign) |

### 📄 Required: `mvr.config.json`

Located in your working directory, this file defines how the package is deployed and registered:

```json
{
  "network": "mainnet",
  "owner": "0x123...abc",
  "app_name": "@myname/app",
  "app_desc": "My App Description",
  "upgrade_cap": "0xabc...def",
  "app_cap": "0xappcap...123",
  "pkg_info": "0xpackageinfo...456",
  "icon_url": "https://example.com/icon.png",
  "homepage_url": "https://myapp.site",
  "documentation_url": "https://docs.myapp.site",
  "contact": "team@myapp.site"
}
```

### 🩹 Field Reference

| Field               | Type   | Required | Description                             |
| ------------------- | ------ | -------- | --------------------------------------- |
| `network`           | string | ✅       | `"mainnet"`, `"testnet"`, or `"devnet"` |
| `owner`             | string | ✅       | Sui address that will own the package   |
| `app_name`          | string | ✅       | MVR name in `@name/app` format          |
| `app_desc`          | string | ✅       | Short description for MVR               |
| `upgrade_cap`       | string | optional | Object ID to upgrade existing package   |
| `app_cap`           | string | optional | AppCap object ID for registration       |
| `pkg_info`          | string | optional | PackageInfo object ID                   |
| `icon_url`          | string | optional | Icon displayed in registry UI           |
| `homepage_url`      | string | optional | Official app/site URL                   |
| `documentation_url` | string | optional | Docs URL                                |
| `contact`           | string | optional | Email or support contact                |

> ℹ️ If `app_name` or `app_desc` is missing, MVR registration will be skipped.

### 📄 Output Artifacts

| File                 | Description                                             |
| -------------------- | ------------------------------------------------------- |
| `bytecode.dump.json` | Compiled base64-encoded Move bytecode                   |
| `deploy.json`        | Deployment result with `package_id`, `upgrade_id`, etc. |
| `mvr.config.json`    | Configuration used for registration                     |
| `mvr.intoto.jsonl`   | SLSA-compatible provenance file                         |

### 📆 MVR Metadata Registration

The following items are registered to the Move Registry (MVR) as metadata:

- `mvr.intoto.jsonl` — SLSA-compatible provenance file
- Deployment transaction digest — the on-chain reference for the published package

This enables:

- ✅ Verifiable origin of Move packages

### 📂 Advanced Usage

- Combine with GitHub OIDC + GitSigner for secure key separation
- Use `upgrade_cap` to automate upgrades across environments
- Integrate with your CI/CD via `upload-artifact` / `download-artifact`

### 📁 GitHub

This repository includes:

- 🧩 **Move package**: [`hello_world`](https://github.com/zktx-io/sui-mvr-example/tree/main/hello_world)
- ⚙️ **GitHub Actions workflow**: [`.github/workflows/deploy.yml`](https://github.com/zktx-io/sui-mvr-example/blob/main/.github/workflows/deploy.yml)
- 📝 **Provenance config**: [`mvr.config.json`](https://github.com/zktx-io/sui-mvr-example/blob/main/hello_world/mvr.config.json)

### 🧱 Based on the Sui Move Intro Course

This example is derived from the official [Sui Move Intro Course – Hello World](https://github.com/sui-foundation/sui-move-intro-course/tree/main/unit-one/example_projects/hello_world).
It demonstrates how even a minimal Move module can be published and verified with full provenance.
