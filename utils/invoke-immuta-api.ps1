function Invoke-ImmutaApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("GET","POST","PUT","PATCH","DELETE")]
        [string]$Method,

        [Parameter(Mandatory=$true)]
        [string]$Endpoint,

        $Body = $null
    )

    if (-not $env:IMMUTA_API_KEY) { throw "IMMUTA_API_KEY is NOT set" }
    if (-not $env:IMMUTA_TENANT)  { throw "IMMUTA_TENANT is NOT set" }

    $headers = @{
        "Authorization" = "Bearer $env:IMMUTA_API_KEY"
        "Content-Type"  = "application/json"
        "Accept"        = "application/json"
    }

    $base = $env:IMMUTA_TENANT.TrimEnd("/")
    $path = if ($Endpoint.StartsWith("/")) { $Endpoint } else { "/$Endpoint" }
    $uri  = "$base$path"

    try {
        if ($null -ne $Body) {
            $json = $Body | ConvertTo-Json -Depth 30
            return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -Body $json -ErrorAction Stop
        } else {
            return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ErrorAction Stop
        }
    }
    catch {
        $status = $null
        $respBody = $null

        # 1) Best source in PowerShell for REST error bodies:
        try {
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                $respBody = $_.ErrorDetails.Message
            }
        } catch {}

        # 2) Fallback: attempt to read response stream
        if (-not $respBody -and $_.Exception.Response) {
            try { $status = [int]$_.Exception.Response.StatusCode } catch {}
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                if ($stream) {
                    $reader = New-Object System.IO.StreamReader($stream)
                    $respBody = $reader.ReadToEnd()
                }
            } catch {}
        }

        $msg = "Failed to call Immuta API: $Method $uri"
        if ($status) { $msg += "`nHTTP Status: $status" }
        $msg += "`nError: $($_.Exception.Message)"
        if ($respBody) { $msg += "`nResponse Body: $respBody" }

        throw $msg
    }
}