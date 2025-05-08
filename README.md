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

- `network` _(string)_: The Sui network to deploy to. One of "mainnet", "testnet", or "devnet".
- `owner` _(string)_: The address used to deploy the package. Must be authorized to sign.
- `app_name` _(string)_: MVR package name in @name/app format. Required for MVR registration.
- `app_desc` _(string)_: Short description of the package (e.g., "My token standard"). Required for MVR registration.
- `upgrade_cap` _(string, optional)_: If present, triggers an upgrade instead of a fresh deploy.
- `app_cap` _(string, optional)_: Previously created AppCap object ID, used when skipping initial registration.
- `pkg_info` _(string, optional)_: PackageInfo object ID, used during upgrades to update metadata.
- `icon_url` _(string, optional)_: URL pointing to your app’s icon.
- `homepage_url` _(string, optional)_: Official site or landing page.
- `documentation_url` _(string, optional)_: Link to API or developer docs.
- `contact` _(string, optional)_: Email or support contact.

This config file will be used during deployment and provenance generation.

## 🔧 Behavior

- If either `app_name` or `app_desc` is missing, deployment proceeds but MVR registration is skipped.
- If upgrade_cap is provided, it automatically resolves the package_id using the chain state.
- The config file must exist at ${{ inputs.working-directory }}/mvr.config.json.

## 📤 Output

| File               | Description                                                                 |
| ------------------ | --------------------------------------------------------------------------- |
| bytecode.dump.json | Base64-encoded compiled Move modules and dependencies.                      |
| deploy.json        | Deployment result including package_id, upgrade_id, and tx metadata.        |
| mvr.config.json    | MVR deployment configuration used for provenance and metadata registration. |
| mvr.intoto.jsonl   | SLSA-compatible provenance file proving verifiable deployment integrity.    |

These artifacts are reused across the provenance, verify, and mvr-register jobs for full end-to-end verification and Move Registry integration.

## 🛠 Example

```yaml
- name: Build and Upload Move Bytecode
  uses: zktx-io/sui-mvr-provenance@v0.0.30
  with:
    working-directory: ./my-move-package
```

## 📦 MVR Metadata Registration

This workflow registers the following three files as **metadata** in the **Move Registry (MVR)** during the deployment process:

| File Name          | Description                                                                                                                        |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| `deploy.json`      | Contains information about the deployed Move package, such as `package_id`, `upgrade_id`, `digest`, `modules`, and `dependencies`. |
| `mvr.config.json`  | Defines deployment configuration, including `app_name`, `owner`, `network`, `upgrade_id`, etc.                                     |
| `mvr.intoto.jsonl` | A **provenance file** generated via SLSA & Sigstore to verify the integrity and authenticity of the above files.                   |

This metadata is stored in MVR to enable:

- ✅ Verifiable **origin and integrity** of Move packages
- 🔁 Separate management of the same named packages across **mainnet and testnet**
- 🔎 Support for **named references** like `@suins/appName::module::function`

> 💡 If `app_name` is not provided, MVR registration is skipped. The name must follow the format `@suinsName/appName` (e.g., `@mvr/counter`).
