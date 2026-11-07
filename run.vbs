Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

ScriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
PsScript = """" & ScriptDir & "\sveto4.ps1"""
WshShell.Run "powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File " & PsScript, 0, False
