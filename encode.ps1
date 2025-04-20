$url = 'https://api.github.com/repos/xsdementevx/launcher/contents/launcher_dll.exe'
$bytes = [System.Text.Encoding]::UTF8.GetBytes($url)
$encodedString = [Convert]::ToBase64String($bytes)
$decodedString = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encodedString))
Write-Host "Original URL:"
$url
Write-Host "`nBase64 encoded:"
$encodedString
Write-Host "`nDecoded:"
$decodedString 