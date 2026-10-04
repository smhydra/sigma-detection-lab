<#
.SYNOPSIS
    Sigma Detection Engineering Portfolio Local Runner
.DESCRIPTION
    Runs automated schema validation, SIEM multi-backend conversions, and MITRE ATT&CK coverage matrix generation.
#>

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  Sigma Detection Engineering Suite Runner        " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

Write-Host "`n[*] 1/3 Validating Sigma Rules Schema..." -ForegroundColor Yellow
python tools/validate_rules.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Validation failed!" -ForegroundColor Red
    exit 1
}

Write-Host "`n[*] 2/3 Batch Converting Rules to Splunk, Elastic, & Kusto..." -ForegroundColor Yellow
python tools/convert_rules.py

Write-Host "`n[*] 3/3 Generating MITRE ATT&CK Matrix Report..." -ForegroundColor Yellow
python tools/generate_mitre_matrix.py

Write-Host "`n[+] All portfolio verification steps completed successfully!" -ForegroundColor Green
