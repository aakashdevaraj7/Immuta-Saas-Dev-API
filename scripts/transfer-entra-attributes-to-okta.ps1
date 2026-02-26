# scripts/transfer-entra-attributes-to-okta.ps1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [ValidateSet("Single", "All")]
    [string]$Mode,

    # In Single mode, you can enter email or userid
    [string]$SourceIdentifier,

    # Optional override for how to find the target user
    [string]$TargetIdentifier,

    # Where to read attributes from on the source user
    [ValidateSet("iamAuthorizations", "authorizations", "bimAuthorizations")]
    [string]$SourceAuthorizationField = "iamAuthorizations",

    # Explicit keys to copy (your set)
    [string[]]$Keys = @(
        "profile.businessunit",
        "profile.country",
        "profile.division",
        "profile.employeetype",
        "profile.jobrole"
    ),

    # If set, overrides -Keys and copies ANY key starting with this prefix (e.g. "profile.")
    [string]$KeyPrefix,

    # Remove existing values on target for keys we are copying
    [switch]$Replace,

    # Print-only mode
    [switch]$DryRun,

    # For Mode=All
    [int]$PageSize = 200,
    [int]$MaxPages = 500,
    [int]$MaxUsers = 0,

    # Optional report path
    [string]$ReportPath
)

. (Join-Path $PSScriptRoot "..\load-env.ps1")
. (Join-Path $PSScriptRoot "..\utils\invoke-immuta-api.ps1")

# ---------------- Utility helpers ----------------

function Read-Choice {
    param(
        [Parameter(Mandatory=$true)][string]$Prompt,
        [Parameter(Mandatory=$true)][string[]]$Allowed
    )
    while ($true) {
        $val = (Read-Host $Prompt).Trim()
        foreach ($a in $Allowed) {
            if ($val.Equals($a, [System.StringComparison]::OrdinalIgnoreCase)) { return $a }
        }
        Write-Host ("Invalid input. Allowed: " + ($Allowed -join ", ")) -ForegroundColor Yellow
    }
}

function ConvertTo-NormalizedText {
    param([string]$Raw)
    if ($null -eq $Raw) { return $null }
    return $Raw.Trim().Trim('"').Trim("'").Trim().TrimStart("[").TrimEnd("]")
}

function Test-IsEmailLike {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return ($Text -match "@")
}

# ---------------- IAM helpers ----------------

function Get-BimIams {
    # GET /bim/iam
    $iams = Invoke-ImmutaApi -Method GET -Endpoint "/bim/iam"
    return @($iams)
}

function Get-IamLabel {
    param($Iam)
    if ($Iam.displayName) { return [string]$Iam.displayName }
    if ($Iam.name)        { return [string]$Iam.name }
    return [string]$Iam.id
}

function Select-Iam {
    param(
        [Parameter(Mandatory=$true)][string]$RoleLabel,
        [Parameter(Mandatory=$true)]$Iams
    )
    Write-Host ""
    Write-Host ("Select IAM for {0}:" -f $RoleLabel) -ForegroundColor Cyan

    for ($i = 0; $i -lt $Iams.Count; $i++) {
        $label = Get-IamLabel $Iams[$i]
        Write-Host ("  {0}) {1} (id={2}, type={3})" -f ($i+1), $label, $Iams[$i].id, $Iams[$i].type)
    }

    while ($true) {
        $raw = (Read-Host "Pick a number").Trim()
        $n = 0
        if ([int]::TryParse($raw, [ref]$n) -and $n -ge 1 -and $n -le $Iams.Count) {
            return $Iams[$n-1]
        }
        Write-Host "Invalid selection." -ForegroundColor Yellow
    }
}

# ---------------- User search helpers ----------------

function Search-BimUsers {
    param(
        [Parameter(Mandatory=$true)][string]$IamId,
        [string]$UserIdPartial,
        [string]$EmailPartial,
        [int]$Size = 50,
        [int]$Offset = 0
    )

    # /bim/user supports: iamid, userid, email, size, offset
    $qs = @(
        "iamid=$([uri]::EscapeDataString($IamId))",
        "size=$Size",
        "offset=$Offset"
    )

    if ($UserIdPartial) { $qs += "userid=$([uri]::EscapeDataString($UserIdPartial))" }
    if ($EmailPartial)  { $qs += "email=$([uri]::EscapeDataString($EmailPartial))" }

    $endpoint = "/bim/user?" + ($qs -join "&")
    return Invoke-ImmutaApi -Method GET -Endpoint $endpoint
}

function Select-UserHit {
    param(
        [Parameter(Mandatory=$true)][string]$PromptLabel,
        [Parameter(Mandatory=$true)]$Hits
    )
    Write-Host ""
    Write-Host $PromptLabel -ForegroundColor Cyan

    for ($i = 0; $i -lt $Hits.Count; $i++) {
        $h = $Hits[$i]
        $email = ""
        try { $email = [string]$h.profile.email } catch {}
        Write-Host ("  {0}) userid={1} | email={2} | numericId={3}" -f ($i+1), $h.userid, $email, $h.id)
    }

    while ($true) {
        $raw = (Read-Host "Pick a number").Trim()
        $n = 0
        if ([int]::TryParse($raw, [ref]$n) -and $n -ge 1 -and $n -le $Hits.Count) {
            return $Hits[$n-1]
        }
        Write-Host "Invalid selection." -ForegroundColor Yellow
    }
}

function Find-UserInIam {
    param(
        [Parameter(Mandatory=$true)][string]$IamId,
        [Parameter(Mandatory=$true)][string]$Identifier
    )

    $Identifier = ConvertTo-NormalizedText $Identifier
    if ([string]::IsNullOrWhiteSpace($Identifier)) { return $null }

    $hits = @()

    # Search by email if it looks like email
    if (Test-IsEmailLike $Identifier) {
        $r1 = Search-BimUsers -IamId $IamId -EmailPartial $Identifier -Size 200
        if ($r1.hits) { $hits += @($r1.hits) }
    }

    # Always search by userid too
    $r2 = Search-BimUsers -IamId $IamId -UserIdPartial $Identifier -Size 200
    if ($r2.hits) { $hits += @($r2.hits) }

    $hits = $hits | Sort-Object id -Unique
    if (-not $hits -or $hits.Count -eq 0) { return $null }

    # Prefer exact matches
    $exact = @()
    foreach ($h in $hits) {
        $email = $null
        try { $email = [string]$h.profile.email } catch {}
        if ($h.userid -eq $Identifier) { $exact += $h; continue }
        if ($email -and $email -eq $Identifier) { $exact += $h; continue }
    }

    if ($exact.Count -eq 1) { return $exact[0] }
    if ($exact.Count -gt 1) { return (Select-UserHit -PromptLabel "Multiple exact matches found. Select the correct user:" -Hits $exact) }

    if ($hits.Count -eq 1) { return $hits[0] }
    return (Select-UserHit -PromptLabel "Multiple candidates found. Select the correct user:" -Hits $hits)
}

function Get-BimUserAggregated {
    param(
        [Parameter(Mandatory=$true)][string]$IamId,
        [Parameter(Mandatory=$true)][int]$NumericUserId
    )
    # GET /bim/iam/{iamid}/user/{id}
    return Invoke-ImmutaApi -Method GET -Endpoint "/bim/iam/$IamId/user/$NumericUserId"
}

# ---------------- Authorization copy helpers ----------------

function Get-AuthPairs {
    param(
        [Parameter(Mandatory=$true)]$AuthObject,
        [string[]]$AllowedKeys,
        [string]$Prefix
    )

    $pairs = New-Object System.Collections.Generic.List[object]

    foreach ($prop in $AuthObject.PSObject.Properties) {
        $key = [string]$prop.Name

        if ($Prefix) {
            if (-not $key.StartsWith($Prefix)) { continue }
        } else {
            if ($AllowedKeys -and $AllowedKeys.Count -gt 0 -and ($AllowedKeys -notcontains $key)) { continue }
        }

        foreach ($v in @($prop.Value)) {
            if ($null -eq $v) { continue }
            $pairs.Add([pscustomobject]@{ Key=$key; Value=[string]$v })
        }
    }

    return $pairs
}

function Invoke-AddAuthorization {
    param(
        [Parameter(Mandatory=$true)][string]$IamId,
        [Parameter(Mandatory=$true)][string]$TargetUserIdModel,
        [Parameter(Mandatory=$true)][string]$Key,
        [Parameter(Mandatory=$true)][string]$Value
    )

    $u = [uri]::EscapeDataString($TargetUserIdModel)
    $k = [uri]::EscapeDataString($Key)
    $v = [uri]::EscapeDataString($Value)

    # PUT /bim/iam/{iamid}/user/{userid}/authorizations/{key}/{value}
    return Invoke-ImmutaApi -Method PUT -Endpoint "/bim/iam/$IamId/user/$u/authorizations/$k/$v"
}

function Invoke-RemoveAuthorization {
    param(
        [Parameter(Mandatory=$true)][string]$IamId,
        [Parameter(Mandatory=$true)][string]$TargetUserIdModel,
        [Parameter(Mandatory=$true)][string]$Key,
        [Parameter(Mandatory=$true)][string]$Value
    )

    $u = [uri]::EscapeDataString($TargetUserIdModel)
    $k = [uri]::EscapeDataString($Key)
    $v = [uri]::EscapeDataString($Value)

    # DELETE /bim/iam/{iamid}/user/{userid}/authorizations/{key}/{value}
    return Invoke-ImmutaApi -Method DELETE -Endpoint "/bim/iam/$IamId/user/$u/authorizations/$k/$v"
}

function Test-HasAuthPair {
    param(
        $AuthObject,
        [Parameter(Mandatory=$true)][string]$Key,
        [Parameter(Mandatory=$true)][string]$Value
    )
    if (-not $AuthObject) { return $false }
    if ($AuthObject.PSObject.Properties.Name -notcontains $Key) { return $false }
    return (@($AuthObject.$Key) -contains $Value)
}

# ---------------- Main flow ----------------

# Prompt for Mode if not provided
if ([string]::IsNullOrWhiteSpace($Mode)) {
    $Mode = Read-Choice -Prompt "Mode (Single/All)" -Allowed @("Single","All")
}

# Prompt for Single identifier if not provided
if ($Mode -eq "Single" -and [string]::IsNullOrWhiteSpace($SourceIdentifier)) {
    $SourceIdentifier = ConvertTo-NormalizedText (Read-Host "Enter SOURCE user identifier (userid or email)")
    if ([string]::IsNullOrWhiteSpace($SourceIdentifier)) { throw "SourceIdentifier cannot be empty." }
} else {
    $SourceIdentifier = ConvertTo-NormalizedText $SourceIdentifier
    $TargetIdentifier = ConvertTo-NormalizedText $TargetIdentifier
}

# Report setup
if (-not $ReportPath) {
    $projectRoot = Split-Path $PSScriptRoot -Parent
    $logsDir = Join-Path $projectRoot "logs"
    if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir | Out-Null }
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $ReportPath = Join-Path $logsDir "attribute-transfer-$stamp.csv"
}
$report = New-Object System.Collections.Generic.List[object]

# Select IAMs
$iams = Get-BimIams
$sourceIam = Select-Iam -RoleLabel "SOURCE (Entra)" -Iams $iams
$targetIam = Select-Iam -RoleLabel "TARGET (Okta)"  -Iams $iams

$sourceIamId = $sourceIam.id
$targetIamId = $targetIam.id

Write-Host ""
Write-Host ("Source IAM: {0} (id={1})" -f (Get-IamLabel $sourceIam), $sourceIamId) -ForegroundColor Green
Write-Host ("Target IAM: {0} (id={1})" -f (Get-IamLabel $targetIam), $targetIamId) -ForegroundColor Green
Write-Host ("Reading source attributes from: {0}" -f $SourceAuthorizationField) -ForegroundColor DarkGray

# Build source user list
$sourceUserHits = @()

if ($Mode -eq "Single") {
    $srcHit = Find-UserInIam -IamId $sourceIamId -Identifier $SourceIdentifier
    if (-not $srcHit) {
        throw "Source user not found in SOURCE IAM using identifier '$SourceIdentifier' (iamid=$sourceIamId). Try using userid instead of email, or vice versa."
    }
    $sourceUserHits = @($srcHit)
}
else {
    Write-Host ""
    Write-Host "Mode=All: paging through source IAM users..." -ForegroundColor Cyan

    $offset = 0
    for ($page = 1; $page -le $MaxPages; $page++) {
        $resp = Search-BimUsers -IamId $sourceIamId -Size $PageSize -Offset $offset
        if (-not $resp.hits) { break }

        $hits = @($resp.hits)
        if ($hits.Count -eq 0) { break }

        $sourceUserHits += $hits
        $offset += $PageSize

        if ($MaxUsers -gt 0 -and $sourceUserHits.Count -ge $MaxUsers) {
            $sourceUserHits = $sourceUserHits | Select-Object -First $MaxUsers
            break
        }

        if ($resp.count -and $sourceUserHits.Count -ge [int]$resp.count) { break }
        if ($hits.Count -lt $PageSize) { break }
    }

    Write-Host ("Users to process: {0}" -f $sourceUserHits.Count) -ForegroundColor Green
}

foreach ($srcHit in $sourceUserHits) {
    $srcUserId = $srcHit.userid
    $srcEmail = ""
    try { $srcEmail = [string]$srcHit.profile.email } catch {}

    Write-Host ""
    Write-Host ("==== SOURCE user: userid={0} | email={1} | numericId={2} ====" -f $srcUserId, $srcEmail, $srcHit.id) -ForegroundColor Cyan

    # Find target user
    $targetLookup = $TargetIdentifier
    if ([string]::IsNullOrWhiteSpace($targetLookup)) {
        if (-not [string]::IsNullOrWhiteSpace($srcEmail)) { $targetLookup = $srcEmail }
        else { $targetLookup = $srcUserId }
    }

    $tgtHit = Find-UserInIam -IamId $targetIamId -Identifier $targetLookup
    if (-not $tgtHit) {
        $report.Add([pscustomobject]@{
            timestamp = (Get-Date).ToString("s")
            sourceIam = $sourceIamId
            targetIam = $targetIamId
            sourceUserId = $srcUserId
            sourceEmail  = $srcEmail
            targetLookup = $targetLookup
            action = "SkipNoTargetUser"
            key    = ""
            value  = ""
            appliedVia = ""
            verifiedInBimAuthorizations = ""
            details = "No target match found"
        })
        continue
    }

    # Read aggregated records
    $srcAgg = Get-BimUserAggregated -IamId $sourceIamId -NumericUserId ([int]$srcHit.id)
    $tgtAggBefore = Get-BimUserAggregated -IamId $targetIamId -NumericUserId ([int]$tgtHit.id)

    $srcAuth = $srcAgg.$SourceAuthorizationField
    if (-not $srcAuth) {
        $report.Add([pscustomobject]@{
            timestamp = (Get-Date).ToString("s")
            sourceIam = $sourceIamId
            targetIam = $targetIamId
            sourceUserId = $srcUserId
            sourceEmail  = $srcEmail
            targetLookup = $targetLookup
            action = "SkipNoSourceAuthVisible"
            key    = ""
            value  = ""
            appliedVia = ""
            verifiedInBimAuthorizations = ""
            details = "SourceAuthorizationField not present/visible (may require USER_ADMIN)"
        })
        continue
    }

    $pairs = Get-AuthPairs -AuthObject $srcAuth -AllowedKeys $Keys -Prefix $KeyPrefix
    Write-Host ("Pairs to copy: {0}" -f $pairs.Count) -ForegroundColor DarkGray
    if ($pairs.Count -eq 0) { continue }

    # Replace mode: remove existing target values for keys we will copy (based on effective authorizations)
    if ($Replace -and $tgtAggBefore.authorizations) {
        $keysToReplace = $pairs | Select-Object -ExpandProperty Key -Unique
        foreach ($k in $keysToReplace) {
            if ($tgtAggBefore.authorizations.PSObject.Properties.Name -contains $k) {
                foreach ($existing in @($tgtAggBefore.authorizations.$k)) {
                    if ($DryRun) {
                        Write-Host ("[DryRun] Would REMOVE {0}={1}" -f $k, $existing) -ForegroundColor DarkGray
                    } else {
                        if ($PSCmdlet.ShouldProcess($tgtHit.userid, ("REMOVE {0}={1}" -f $k, $existing))) {
                            Invoke-RemoveAuthorization -IamId $targetIamId -TargetUserIdModel $tgtHit.userid -Key $k -Value ([string]$existing) | Out-Null
                        }
                    }
                }
            }
        }
    }

    # Apply
    foreach ($p in $pairs) {
        $apiIndicator = "PUT /bim/iam/$targetIamId/user/$($tgtHit.userid)/authorizations/$($p.Key)/$($p.Value)"

        if ($DryRun) {
            Write-Host ("[DryRun][Immuta API] {0}" -f $apiIndicator) -ForegroundColor DarkGray
            continue
        }

        if ($PSCmdlet.ShouldProcess($tgtHit.userid, ("ADD {0}={1}" -f $p.Key, $p.Value))) {
            # This is your explicit indicator that transfer is via Immuta API
            Write-Host ("[Immuta API] {0}" -f $apiIndicator) -ForegroundColor Yellow
            Invoke-AddAuthorization -IamId $targetIamId -TargetUserIdModel $tgtHit.userid -Key $p.Key -Value $p.Value | Out-Null
        }
    }

    # Verify
    $tgtAggAfter = Get-BimUserAggregated -IamId $targetIamId -NumericUserId ([int]$tgtHit.id)

    foreach ($p in $pairs) {
        $verified = Test-HasAuthPair -AuthObject $tgtAggAfter.bimAuthorizations -Key $p.Key -Value $p.Value
        if ($verified) {
            Write-Host ("Verified in bimAuthorizations (Immuta-set): {0}={1}" -f $p.Key, $p.Value) -ForegroundColor Green
        } else {
            Write-Host ("NOT verified in bimAuthorizations: {0}={1}" -f $p.Key, $p.Value) -ForegroundColor Red
        }

        $report.Add([pscustomobject]@{
            timestamp = (Get-Date).ToString("s")
            sourceIam = $sourceIamId
            targetIam = $targetIamId
            sourceUserId = $srcUserId
            sourceEmail  = $srcEmail
            targetUserId = $tgtHit.userid
            key = $p.Key
            value = $p.Value
            appliedVia = "ImmutaBimApi"
            verifiedInBimAuthorizations = [string]$verified
            details = ""
        })
    }
}

$report | Export-Csv -NoTypeInformation -Path $ReportPath
Write-Host ""
Write-Host ("Report written: {0}" -f $ReportPath) -ForegroundColor Green
Write-Host "Done." -ForegroundColor Green





# 1) Single user (DryRun first)
# cd "C:\Users\jvr8435\Imu Saas Dev Api"
# .\scripts\transfer-entra-attributes-to-okta.ps1 -Mode Single -SourceIdentifier "aakash.devaraj@takeda.com" -DryRun

# 2) Single user (apply)
# .\scripts\transfer-entra-attributes-to-okta.ps1 -Mode Single -SourceIdentifier "aakash.devaraj@takeda.com"

# 3) Copy all profile.* keys (instead of only the 5)
# .\scripts\transfer-entra-attributes-to-okta.ps1 -Mode Single -SourceIdentifier "aakash.devaraj@takeda.com" -KeyPrefix "profile." -DryRun

# 4) All users (start small with MaxUsers)
# .\scripts\transfer-entra-attributes-to-okta.ps1 -Mode All -MaxUsers 50 -DryRun