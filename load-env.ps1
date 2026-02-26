# load-env.ps1
$envFile = "$PSScriptRoot/.env"

if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        # Ignore empty lines or comments
        if ($_ -match "^\s*([^#=]+)\s*=\s*(.+)$") {
            $varName  = $matches[1].Trim()
            $varValue = $matches[2].Trim()
            # Correct way to assign env variable using variable name
            Set-Item -Path "Env:$varName" -Value $varValue
        }
    }
    Write-Host "Environment variables loaded from .env"
} else {
    Write-Host ".env file not found!"
}