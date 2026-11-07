param (
    [switch]$AutoEnable
)
$ProgressPreference = 'SilentlyContinue'

# ---------------------------
# Run as Administrator
# ---------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# ---------------------------
# Imports & Win32 API
# ---------------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$Signature = @"
[DllImport("user32.dll", CharSet = CharSet.Auto)]
public static extern bool DestroyIcon(IntPtr handle);
"@
$User32 = Add-Type -MemberDefinition $Signature -Name "User32" -Namespace "Win32" -PassThru

# ---------------------------
# Colors & Icons Global Setup
# ---------------------------
$colorRed    = [System.Drawing.Color]::FromArgb(239, 67, 73)
$colorBlue   = [System.Drawing.Color]::FromArgb(0, 122, 204)
$colorGray   = [System.Drawing.Color]::FromArgb(73, 73, 73)
$colorGreen  = [System.Drawing.Color]::FromArgb(149, 222, 85)
$colorYellow = [System.Drawing.Color]::FromArgb(255, 209, 79)

function Create-CircleIcon([System.Drawing.Color]$color) {
    $bitmap = [System.Drawing.Bitmap]::new(24, 24)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.SmoothingMode = "AntiAlias"
        $brush = [System.Drawing.SolidBrush]::new($color)
        try {
            $graphics.FillEllipse($brush, 0, 0, 23, 23)
            $hIcon = $bitmap.GetHicon()
            $icon = [System.Drawing.Icon]::FromHandle($hIcon).Clone()
            [Win32.User32]::DestroyIcon($hIcon) | Out-Null
            return $icon
        } finally {
            $brush.Dispose()
        }
    } finally {
        $graphics.Dispose()
        $bitmap.Dispose()
    }
}

$global:StaticIconCache = @{}
function Get-StaticIcon([System.Drawing.Color]$color) {
    $key = $color.ToArgb()
    if (-not $global:StaticIconCache.ContainsKey($key)) {
        $global:StaticIconCache[$key] = Create-CircleIcon($color)
    }
    return $global:StaticIconCache[$key]
}

# ---------------------------
# Global Variables & App Config
# ---------------------------
$RulePrefix = "KS-"
$global:KillSwitchState = $false
$global:KillSwitchInterfaces = [System.Collections.Generic.List[string]]::new()
$global:LocalTraffic = $false
$global:NatTraffic = $false
$global:IsAnimating = $false
$global:CurrentIconColor = $colorYellow
$global:localSubnets = @("192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "fc00::/7")

$global:TargetApps = @("happ", "hiddify")

# ---------------------------
# App Process & Firewall Helpers
# ---------------------------
function Sync-AppRulesForInterface {
    param(
        [string]$ifaceName,
        [bool]$isActivating
    )

    $matchedApp = $null
    foreach ($appName in $global:TargetApps) {
        if ($ifaceName -like "*$appName*") {
            $matchedApp = $appName
            break
        }
    }

    if (-not $matchedApp) { return }

    if ($isActivating) {
        $appPaths = [System.Collections.Generic.HashSet[string]]::new()
        $parentPids = [System.Collections.Generic.HashSet[uint32]]::new()

        $allWmiProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue

        # 1. Находим основные процессы (Happ, happd) и сохраняем их PID
        foreach ($p in $allWmiProcs) {
            if ($p.Name -and $p.Name -like "*$matchedApp*") {
                if ($p.ExecutablePath) {
                    $null = $appPaths.Add($p.ExecutablePath)
                }
                if ($p.ProcessId) {
                    $null = $parentPids.Add([uint32]$p.ProcessId)
                }
            }
        }

        # 2. Находим дочерние процессы (например, xray.exe), запущенные ими
        if ($parentPids.Count -gt 0) {
            foreach ($p in $allWmiProcs) {
                if ($p.ParentProcessId -and $parentPids.Contains([uint32]$p.ParentProcessId)) {
                    if ($p.ExecutablePath) {
                        $null = $appPaths.Add($p.ExecutablePath)
                    }
                }
            }
        }

        # 3. Создаем правила для всех найденных файлов (.exe)
        foreach ($exePath in $appPaths) {
            if (Test-Path $exePath) {
                $exeName = [System.IO.Path]::GetFileNameWithoutExtension($exePath)
                $ruleName = "${RulePrefix}App-$matchedApp-$exeName"

                try {
                    Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                    New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Program $exePath -Action Allow -Profile Any -ErrorAction Stop | Out-Null
                } catch {}
            }
        }
    } else {
        $otherActiveInterfaces = $global:KillSwitchInterfaces | Where-Object { $_ -like "*$matchedApp*" }
        if (-not $otherActiveInterfaces) {
            Get-NetFirewallRule -DisplayName "${RulePrefix}App-$matchedApp-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        }
    }
}

# ---------------------------
# Logic
# ---------------------------
function Get-CurrentKSColor {
    if (-not $global:KillSwitchState) { return $colorRed }
    if ($global:KillSwitchInterfaces.Count -eq 0) { return $colorGray }

    $adapters = Get-NetAdapter | Where-Object { $global:KillSwitchInterfaces -contains $_.Name }
    if (-not $adapters) { return $colorBlue }
    if ($adapters | Where-Object { $_.Status -eq "Up" }) { return $colorGreen }

    return $colorGray
}

function Update-Tooltip {
    $statusKS  = if ($global:KillSwitchState) { "ON" } else { "OFF" }
    $statusLAN = if ($global:LocalTraffic)    { "ON" } else { "OFF" }
    $statusNAT = if ($global:NatTraffic)      { "ON" } else { "OFF" }
    $ifaceText = if ($global:KillSwitchInterfaces.Count -gt 0) { "($($global:KillSwitchInterfaces.Count))" } else { "0" }

    $tooltip = "Kill Switch: $statusKS`nAllow LAN: $statusLAN`nAllow NAT: $statusNAT`nInterfaces: $ifaceText"
    $global:tray.Text = if ($tooltip.Length -gt 63) { $tooltip.Substring(0, 60) + "..." } else { $tooltip }
}

function Smooth-SetIconColor($fromColor, $toColor) {
    if ($fromColor.ToArgb() -eq $toColor.ToArgb()) { return }
    $global:IsAnimating = $true
    try {
        $steps = 8
        foreach ($i in 1..$steps) {
            $r = [math]::Round($fromColor.R + ($toColor.R - $fromColor.R) * $i / $steps)
            $g = [math]::Round($fromColor.G + ($toColor.G - $fromColor.G) * $i / $steps)
            $b = [math]::Round($fromColor.B + ($toColor.B - $fromColor.B) * $i / $steps)

            $c = [System.Drawing.Color]::FromArgb(255, $r, $g, $b)

            $tempIcon = Create-CircleIcon($c)
            $oldIcon = $global:tray.Icon
            $global:tray.Icon = $tempIcon
            if ($oldIcon -and -not ($global:StaticIconCache.ContainsValue($oldIcon))) { $oldIcon.Dispose() }

            $global:CurrentIconColor = $c
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Milliseconds 15
        }
        $global:tray.Icon = Get-StaticIcon($toColor)
    } catch {
        $global:tray.Icon = Get-StaticIcon($toColor)
    } finally {
        $global:IsAnimating = $false
    }
}

function Show-BusyIcon([scriptblock]$Action) {
    $global:IsAnimating = $true
    $baseColor = Get-CurrentKSColor
    Smooth-SetIconColor $baseColor $colorYellow
    & $Action
    Smooth-SetIconColor $colorYellow (Get-CurrentKSColor)
    Update-Tooltip
    $global:IsAnimating = $false
}

function Enable-KillSwitch {
    Show-BusyIcon {
        Set-NetFirewallProfile -All -DefaultOutboundAction Block
        $global:KillSwitchState = $true
    }
    Update-UI -FetchRules
}

function Disable-KillSwitch {
    Show-BusyIcon {
        Set-NetFirewallProfile -All -DefaultOutboundAction Allow
        $global:KillSwitchState = $false
    }
    Update-UI -FetchRules
}

function Toggle-AllowLAN {
    Show-BusyIcon {
        $global:LocalTraffic = -not $global:LocalTraffic
        foreach ($subnet in $global:localSubnets) {
            $rName = "${RulePrefix}LAN-Allow-$subnet"
            $existing = Get-NetFirewallRule -DisplayName $rName -ErrorAction SilentlyContinue
            if (-not $existing) {
                New-NetFirewallRule -DisplayName $rName -Direction Outbound -RemoteAddress $subnet -Action Allow -Profile Any
            }
            if ($global:LocalTraffic) { Enable-NetFirewallRule -DisplayName $rName }
            else { Disable-NetFirewallRule -DisplayName $rName }
        }
    }
    Update-UI -FetchRules
}

function Toggle-AllowNAT {
    Show-BusyIcon {
        $global:NatTraffic = -not $global:NatTraffic
        $rName = "${RulePrefix}NAT-Allow"

        $existing = Get-NetFirewallRule -DisplayName $rName -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-NetFirewallRule -DisplayName $rName -Direction Outbound -Program "System" -Action Allow -Profile Any
        }

        if ($global:NatTraffic) { Enable-NetFirewallRule -DisplayName $rName }
        else { Disable-NetFirewallRule -DisplayName $rName }
    }
    Update-UI -FetchRules
}

function Toggle-KillSwitchInterface($iface) {
    Show-BusyIcon {
        if ($iface -eq "None") {
            Get-NetFirewallRule -DisplayName "${RulePrefix}Allow-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
            Get-NetFirewallRule -DisplayName "${RulePrefix}App-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
            $global:KillSwitchInterfaces.Clear()
        } else {
            $ruleName = "${RulePrefix}Allow-$iface"
            if ($global:KillSwitchInterfaces.Contains($iface)) {
                $global:KillSwitchInterfaces.Remove($iface) | Out-Null
                Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
                Sync-AppRulesForInterface -ifaceName $iface -isActivating $false
            } else {
                $global:KillSwitchInterfaces.Add($iface)
                if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                    New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -InterfaceAlias $iface -Action Allow -Profile Any
                } else {
                    Enable-NetFirewallRule -DisplayName $ruleName
                }
                Sync-AppRulesForInterface -ifaceName $iface -isActivating $true
            }
        }
    }
    Update-UI -FetchRules
}

# ---------------------------
# UI Management
# ---------------------------
function Update-UI {
    param([switch]$FetchRules)
    try {
        $global:menuItemToggle.Text = if ($global:KillSwitchState) { "Turn OFF" } else { "Turn ON" }
        $global:menuItemAllowLAN.Checked = $global:LocalTraffic
        $global:menuItemAllowLAN.Enabled = $global:KillSwitchState
        $global:menuItemAllowNAT.Checked = $global:NatTraffic
        $global:menuItemAllowNAT.Enabled = $global:KillSwitchState
        $global:menuItemInterfaces.Enabled = $global:KillSwitchState
        $global:menuItemRules.Enabled = $global:KillSwitchState

        $currentAdapters = Get-NetAdapter | Where-Object { $_.Status -ne "Disconnected" } | Select-Object -ExpandProperty Name

        if ($global:KillSwitchInterfaces.Count -gt 0) {
            $global:menuItemInterfaces.Text = "Interfaces: ($($global:KillSwitchInterfaces.Count))"
            $global:menuItemInterfaces.Checked = $true
        } else {
            $global:menuItemInterfaces.Text = "Interfaces"
            $global:menuItemInterfaces.Checked = $false
        }

        $targetNames = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($name in $currentAdapters) { $null = $targetNames.Add($name) }
        foreach ($name in $global:KillSwitchInterfaces) { $null = $targetNames.Add($name) }

        $existingItems = @{}
        $itemsToRemove = [System.Collections.Generic.List[System.Windows.Forms.ToolStripItem]]::new()

        foreach ($item in $global:menuItemInterfaces.DropDownItems) {
            if ($item -is [System.Windows.Forms.ToolStripSeparator]) { continue }
            $existingItems[$item.Text] = $item
        }

        if (-not $existingItems.ContainsKey("None")) {
            $itemNone = [System.Windows.Forms.ToolStripMenuItem]::new("None")
            $itemNone.add_Click({ Toggle-KillSwitchInterface "None" })
            $global:menuItemInterfaces.DropDownItems.Insert(0, $itemNone) | Out-Null
            $existingItems["None"] = $itemNone
        }
        $existingItems["None"].Checked = ($global:KillSwitchInterfaces.Count -eq 0)

        foreach ($name in $targetNames) {
            if ($name -eq "None") { continue }
            if (-not $existingItems.ContainsKey($name)) {
                $newItem = [System.Windows.Forms.ToolStripMenuItem]::new($name)
                $newItem.Tag = $name
                $newItem.add_Click({ Toggle-KillSwitchInterface $this.Tag })
                $global:menuItemInterfaces.DropDownItems.Add($newItem) | Out-Null
                $existingItems[$name] = $newItem
            }
        }

        foreach ($name in $existingItems.Keys) {
            if ($name -eq "None") { continue }
            $item = $existingItems[$name]
            $isStillInSystem = $currentAdapters -contains $name
            $isCurrentlySelected = $global:KillSwitchInterfaces.Contains($name)

            if ($isCurrentlySelected) {
                $item.Checked = $true
                $item.Enabled = $isStillInSystem
            } else {
                $item.Checked = $false
                if (-not $isStillInSystem) { $itemsToRemove.Add($item) }
                else { $item.Enabled = $true }
            }
        }

        foreach ($oldItem in $itemsToRemove) {
            $global:menuItemInterfaces.DropDownItems.Remove($oldItem)
        }

        if ($FetchRules) {
            $ksRules = Get-NetFirewallRule -DisplayName "${RulePrefix}*" -ErrorAction SilentlyContinue
            $global:menuItemRules.DropDownItems.Clear()

            if ($ksRules -and @($ksRules).Count -gt 0) {
                $ruleCount = @($ksRules).Count
                $global:menuItemRules.Text = "Rules ($ruleCount)"

                foreach ($rule in $ksRules) {
                    $statusTag = if ($rule.Enabled -eq 'True') { "" } else { " [Disabled]" }
                    $rItem = [System.Windows.Forms.ToolStripMenuItem]::new("$($rule.DisplayName)$statusTag")
                    $rItem.Enabled = $false
                    $global:menuItemRules.DropDownItems.Add($rItem) | Out-Null
                }
            } else {
                $global:menuItemRules.Text = "Rules"
                $noItem = [System.Windows.Forms.ToolStripMenuItem]::new("No active rules")
                $noItem.Enabled = $false
                $global:menuItemRules.DropDownItems.Add($noItem) | Out-Null
            }
        }

    } catch {
        Write-Debug $_.Exception.Message
    }
}

# ---------------------------
# Initialization & Shutdown
# ---------------------------
function Exit-Application {
    if ($global:timer) { $global:timer.Stop(); $global:timer.Dispose() }
    if ($global:tray) {
        $global:tray.Visible = $false
        $global:tray.Dispose()
    }
    foreach ($key in $global:StaticIconCache.Keys) {
        $global:StaticIconCache[$key].Dispose()
    }
    [System.Windows.Forms.Application]::Exit()
}

function Initialize-Tray {
    param($TrayIcon)
    $menu = [System.Windows.Forms.ContextMenuStrip]::new()
    $global:menuItemToggle = $menu.Items.Add("Turn ON")
    $global:menuItemToggle.add_Click({ if ($global:KillSwitchState) { Disable-KillSwitch } else { Enable-KillSwitch } })
    $menu.Items.Add([System.Windows.Forms.ToolStripSeparator]::new()) | Out-Null

    $global:menuItemAllowLAN = [System.Windows.Forms.ToolStripMenuItem]::new("Allow LAN")
    $global:menuItemAllowLAN.add_Click({ Toggle-AllowLAN })
    $menu.Items.Add($global:menuItemAllowLAN) | Out-Null

    $global:menuItemAllowNAT = [System.Windows.Forms.ToolStripMenuItem]::new("Allow NAT (WSL)")
    $global:menuItemAllowNAT.add_Click({ Toggle-AllowNAT })
    $menu.Items.Add($global:menuItemAllowNAT) | Out-Null

    $global:menuItemInterfaces = [System.Windows.Forms.ToolStripMenuItem]::new("Interfaces")
    $global:menuItemInterfaces.DropDownItems.Add([System.Windows.Forms.ToolStripSeparator]::new()) | Out-Null
    $menu.Items.Add($global:menuItemInterfaces) | Out-Null

    $global:menuItemRules = [System.Windows.Forms.ToolStripMenuItem]::new("Rules")
    $menu.Items.Add($global:menuItemRules) | Out-Null

    $menu.Items.Add([System.Windows.Forms.ToolStripSeparator]::new()) | Out-Null

    $menu.Items.Add("Reset ALL").add_Click({
        Show-BusyIcon {
            Set-NetFirewallProfile -All -DefaultOutboundAction Allow
            Get-NetFirewallRule -DisplayName "${RulePrefix}*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
            $global:KillSwitchInterfaces.Clear()
            $global:KillSwitchState = $false
            $global:LocalTraffic = $false
            $global:NatTraffic = $false
        }
        Update-UI -FetchRules
    }) | Out-Null
    $menu.Items.Add([System.Windows.Forms.ToolStripSeparator]::new()) | Out-Null

    $menu.Items.Add("Exit").add_Click({ Exit-Application }) | Out-Null
    $TrayIcon.ContextMenuStrip = $menu
}

function Initialize-Application {
    $global:tray = [System.Windows.Forms.NotifyIcon]::new()
    $tray.Visible = $true
    $tray.Icon = Get-StaticIcon($colorYellow)
    Initialize-Tray -TrayIcon $tray

    $global:KillSwitchState = ((Get-NetFirewallProfile -Profile Public).DefaultOutboundAction -eq "Block")
    $allRules = Get-NetFirewallRule -DisplayName "${RulePrefix}*" -ErrorAction SilentlyContinue

    $lanRules = $allRules | Where-Object { $_.DisplayName -like "*LAN-Allow-*" }
    $global:LocalTraffic = [bool]($lanRules -and ($lanRules | Where-Object { $_.Enabled -eq 'True' }))

    $natRules = $allRules | Where-Object { $_.DisplayName -eq "${RulePrefix}NAT-Allow" }
    $global:NatTraffic = [bool]($natRules -and ($natRules.Enabled -eq 'True'))

    $ifaceRules = $allRules | Where-Object { $_.DisplayName -like "${RulePrefix}Allow-*" -and $_.Enabled -eq 'True' }
    if ($ifaceRules) {
        foreach ($rule in $ifaceRules) {
            $name = $rule.DisplayName -replace "^${RulePrefix}Allow-", ""
            $global:KillSwitchInterfaces.Add($name)
        }
    }

    Update-UI -FetchRules
    Update-Tooltip
    Smooth-SetIconColor $colorYellow (Get-CurrentKSColor)

    if ($AutoEnable -and -not $global:KillSwitchState) { Enable-KillSwitch }

    $global:timer = [System.Windows.Forms.Timer]::new()
    $global:timer.Interval = 3000
    $global:timer.add_Tick({
        try {
            if (-not $global:IsAnimating) {
                Update-UI
                Update-Tooltip

                $targetColor = Get-CurrentKSColor
                if ($targetColor.ToArgb() -ne $global:CurrentIconColor.ToArgb()) {
                    Smooth-SetIconColor $global:CurrentIconColor $targetColor
                }
            }
        } catch {
            Write-Debug $_.Exception.Message
        }
    })
    $global:timer.Start()
}

Initialize-Application
[System.Windows.Forms.Application]::Run()
