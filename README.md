***

# Immuta SaaS Dev — Entra → Okta Attribute Transfer (PowerShell)

This repository provides PowerShell tooling to copy selected authorization attributes from a **source IAM (Entra)** to a **target IAM (Okta)** inside **Immuta SaaS Dev** using BIM/IAM APIs.  
It supports safe single-user and bulk migrations with verification and audit reporting.

***

## 📂 Repo Structure

    <repo-root>/
      .env
      load-env.ps1
      scripts/
        transfer-entra-attributes-to-okta.ps1
      utils/
        invoke-immuta-api.ps1
      logs/

***

## 🛠 Requirements

*   PowerShell 5.1 or PowerShell 7+
*   Immuta Dev network access
*   Immuta API token (Bearer)
*   Permissions to read/write IAM/BIM authorizations

***

## ⚙️ Configuration

Create a `.env` file:

    IMMUTA_API_KEY=your-token-here
    IMMUTA_TENANT=https://dev-takeda.hosted.immutacloud.com

`load-env.ps1` loads these values, and `invoke-immuta-api.ps1` uses them for all API calls.

***

## 🚀 Quickstart (Recommended: DryRun)

```powershell
cd "<repo-root>"

.\scripts\transfer-entra-attributes-to-okta.ps1 `
  -Mode Single `
  -SourceIdentifier "user@domain.com" `
  -DryRun
```

You will be prompted to select:

*   Source IAM (Entra)
*   Target IAM (Okta)

A CSV report is written to `logs/`.

***

## 🔧 Modes & Key Parameters

### **Single User**

```powershell
-Mode Single
-SourceIdentifier <email-or-userid>
-TargetIdentifier <optional>
```

### **Bulk Mode**

```powershell
-Mode All
-MaxUsers <n>
-PageSize <n>
-DryRun
```

Start with small batches:

```powershell
-Mode All -MaxUsers 10 -DryRun
```

***

## 📑 What Gets Copied

Default keys:

    profile.businessunit
    profile.country
    profile.division
    profile.employeetype
    profile.jobrole

Copy all keys under a prefix:

```powershell
-KeyPrefix "profile."
```

***

## 🔄 Add vs Replace

**Default:** Add-only  
**Replace mode:** Remove existing values, then add new ones:

```powershell
-Replace
```

All mutating operations support:

*   `-DryRun`
*   PowerShell `ShouldProcess` (safe execution)

***

## ✔️ Verification & Reporting

After applying changes:

*   Target user is re-fetched
*   Attributes are verified in `bimAuthorizations`
*   CSV report includes:
    *   source/target users
    *   key/value
    *   appliedVia
    *   verification result

***

## 🧭 Troubleshooting

Common issues:

*   Missing token → check `.env`
*   401/403 → insufficient permissions
*   User not found → wrong IAM or identifier
*   Not verified → retry; propagation delay possible

***

## 📘 Minimal Examples

### Single User

```powershell
.\scripts\transfer-entra-attributes-to-okta.ps1 -Mode Single -SourceIdentifier "user@domain.com"
```

### Bulk Run (DryRun)

```powershell
.\scripts\transfer-entra-attributes-to-okta.ps1 -Mode All -MaxUsers 50 -DryRun
```

***
