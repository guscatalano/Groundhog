# Runs last, after apps, files, env, PATH and registry are in place.
# Exit 0 for success, 3010 to ask for a restart, anything else fails the step.
New-Item -ItemType Directory -Force -Path 'C:\tools\bin' | Out-Null
Write-Output "post-setup done"
