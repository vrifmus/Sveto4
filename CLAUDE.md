# Sveto4: правила проекта

Общие правила лежат в `~/.claude/CLAUDE.md`, описание проекта в `README.md`.

@docs/ROADMAP.md

## Безопасность (файрвол)

- Не запускать `dist\sveto4.exe`, сборки из `src\Sveto4\bin\` и файлы из `legacy/` без явного разрешения пользователя. Сборка (`build.ps1`, `dotnet build`) разрешена, но если программа из `dist` запущена, `build.ps1` её перезапустит: в таком случае сначала спросить.
- Не выполнять команды, меняющие файрвол (`Set-/New-/Remove-/Enable-/Disable-NetFirewall*`, `netsh advfirewall set|add|delete|reset`, запись через COM `HNetCfg.FwPolicy2`), без явного разрешения. Читать настройки можно.
- Перед экспериментами с файрволом предложить резервную копию: `netsh advfirewall export "<путь>\backup.wfw"`.

## Код

- C# на .NET Framework 4.8, WinForms (нативный `ContextMenu`), SDK-style проект `src/Sveto4/Sveto4.csproj`.
- Работа с файрволом только через `Firewall.cs` (COM API), логика в `KillSwitch.cs`, интерфейс в `TrayApp.cs`. Блокирующие вызовы выполняются вне UI-потока (`Task.Run`).
- Ошибки не показываются окнами, а пишутся в журнал (`Log.cs`, `%LOCALAPPDATA%\Sveto4\sveto4.log`).
- Все правила файрвола, которые создаёт программа, называются с префиксом `KS-`. Формат имён совместим с `legacy/`.

## После изменений

- Собрать: `.\build.ps1` (результат в `dist\sveto4.exe`). Проверку запуском выполняет пользователь.
