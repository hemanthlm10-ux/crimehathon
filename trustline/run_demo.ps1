# TrustLine one-shot demo (Windows PowerShell)
param(
  [string]$Evidence = "..\drive-download-20261119T060920Z-1-001",
  [int]$Seeds = 2
)
$ErrorActionPreference = "Stop"
Write-Host "`n=== 1. Investigate ===" -ForegroundColor Cyan
python -m trustline.cli analyse --evidence $Evidence --out out
Write-Host "`n=== 2. Accuracy vs ground truth and vs obvious approaches ===" -ForegroundColor Cyan
python -m trustline.cli evaluate --evidence $Evidence --labels labels/cr26047_labels.csv --out out
Write-Host "`n=== 3. Prevention replay ===" -ForegroundColor Cyan
python -m trustline.cli replay --evidence $Evidence --labels labels/cr26047_labels.csv
Write-Host "`n=== 4. Unseen attack variations ===" -ForegroundColor Cyan
python tools/run_variations.py $Evidence labels/cr26047_labels.csv $Seeds
Write-Host "`nOpen out\report.html" -ForegroundColor Green
