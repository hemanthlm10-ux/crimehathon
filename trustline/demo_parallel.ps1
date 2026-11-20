# TrustLine side-by-side demo for judges (Windows Terminal split panes)
#   Left pane : investigation on the real case evidence (analyse -> evaluate -> replay -> report)
#   Right pane: unseen randomised attack variations
# Usage:  powershell -ExecutionPolicy Bypass -File demo_parallel.ps1
param(
  [string]$Pane = "",
  [string]$Evidence = "..\drive-download-20261119T060920Z-1-001",
  [int]$Seeds = 3
)
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

function Show-Title($text) { Write-Host "`n=== $text ===" -ForegroundColor Cyan }

if ($Pane -eq "case") {
  $Host.UI.RawUI.WindowTitle = "TrustLine - Case CR-26-047"
  Show-Title "1. Investigate the case evidence"
  python -m trustline.cli analyse --evidence $Evidence --out out
  Show-Title "2. Accuracy vs ground truth and vs obvious approaches"
  python -m trustline.cli evaluate --evidence $Evidence --labels labels/cr26047_labels.csv --out out
  Show-Title "3. Prevention replay"
  python -m trustline.cli replay --evidence $Evidence --labels labels/cr26047_labels.csv
  Show-Title "Opening HTML report"
  Start-Process (Join-Path $here "out\report.html")
}
elseif ($Pane -eq "unseen") {
  $Host.UI.RawUI.WindowTitle = "TrustLine - Unseen attacks"
  Show-Title "Unseen randomised attacks ($Seeds per scenario, new random data every run)"
  python tools/run_variations.py $Evidence labels/cr26047_labels.csv $Seeds
  Write-Host "`nDone." -ForegroundColor Green
}
else {
  $self = $MyInvocation.MyCommand.Path
  $wtArgs = @(
    "-w", "new",
    "new-tab", "--title", "`"Case CR-26-047`"", "-d", "`"$here`"",
    "powershell", "-NoExit", "-ExecutionPolicy", "Bypass", "-File", "`"$self`"", "-Pane", "case",
    ";",
    "split-pane", "-V", "--title", "`"Unseen attacks`"", "-d", "`"$here`"",
    "powershell", "-NoExit", "-ExecutionPolicy", "Bypass", "-File", "`"$self`"", "-Pane", "unseen"
  )
  Start-Process wt -ArgumentList $wtArgs
}
