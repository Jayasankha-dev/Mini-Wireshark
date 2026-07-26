#Requires -RunAsAdministrator

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- GLOBAL THREAD-SAFE STATE & VIRTUAL ARRAYS ---
$packetQueue = [System.Collections.Concurrent.ConcurrentQueue[PSCustomObject]]::new()
$captureState = [hashtable]::Synchronized(@{ Running = $false; Filter = "" })
$script:packetArray = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:capturedPacketsInfo = @{}
$script:packetCounter = 0
$script:runspace = $null
$script:psInstance = $null

# --- SETUP MAIN FORM ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "Mini Wireshark Enterprise - Virtual Mode & Thread-Safe Engine"
$form.Size = New-Object System.Drawing.Size(1180, 750)
$form.StartPosition = "CenterScreen"

$tableLayout = New-Object System.Windows.Forms.TableLayoutPanel
$tableLayout.Dock = "Fill"
$tableLayout.ColumnCount = 1
$tableLayout.RowCount = 3
$tableLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 55)))
$tableLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 60)))
$tableLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 40)))
$form.Controls.Add($tableLayout)

# --- TOP CONTROL PANEL ---
$controlPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$controlPanel.Dock = "Fill"
$controlPanel.Padding = New-Object System.Windows.Forms.Padding(6)

$lblAdapter = New-Object System.Windows.Forms.Label
$lblAdapter.Text = "Adapter:"
$lblAdapter.AutoSize = $true
$lblAdapter.Margin = New-Object System.Windows.Forms.Padding(5, 8, 0, 0)
$controlPanel.Controls.Add($lblAdapter)

$cmbAdapters = New-Object System.Windows.Forms.ComboBox
$cmbAdapters.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$cmbAdapters.Size = New-Object System.Drawing.Size(150, 25)

$adapters = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" }
foreach ($adapter in $adapters) {
    $null = $cmbAdapters.Items.Add("$($adapter.InterfaceAlias) ($($adapter.IPAddress))")
}
if ($cmbAdapters.Items.Count -gt 0) { $cmbAdapters.SelectedIndex = 0 }
$controlPanel.Controls.Add($cmbAdapters)

$btnToggle = New-Object System.Windows.Forms.Button
$btnToggle.Text = "Start Capture"
$btnToggle.Size = New-Object System.Drawing.Size(100, 30)
$btnToggle.BackColor = [System.Drawing.Color]::LightGreen
$controlPanel.Controls.Add($btnToggle)

$btnClear = New-Object System.Windows.Forms.Button
$btnClear.Text = "Clear"
$btnClear.Size = New-Object System.Drawing.Size(65, 30)
$controlPanel.Controls.Add($btnClear)

$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Text = "Export CSV"
$btnExport.Size = New-Object System.Drawing.Size(90, 30)
$controlPanel.Controls.Add($btnExport)

$btnImport = New-Object System.Windows.Forms.Button
$btnImport.Text = "Import CSV"
$btnImport.Size = New-Object System.Drawing.Size(90, 30)
$btnImport.BackColor = [System.Drawing.Color]::LightSkyBlue
$controlPanel.Controls.Add($btnImport)

$lblFilter = New-Object System.Windows.Forms.Label
$lblFilter.Text = "Filter:"
$lblFilter.AutoSize = $true
$lblFilter.Margin = New-Object System.Windows.Forms.Padding(8, 8, 0, 0)
$controlPanel.Controls.Add($lblFilter)

$txtFilter = New-Object System.Windows.Forms.TextBox
$txtFilter.Size = New-Object System.Drawing.Size(110, 25)
$controlPanel.Controls.Add($txtFilter)

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text = "Status: Idle | Packets: 0"
$lblStatus.AutoSize = $true
$lblStatus.Margin = New-Object System.Windows.Forms.Padding(10, 8, 0, 0)
$lblStatus.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$controlPanel.Controls.Add($lblStatus)

$tableLayout.Controls.Add($controlPanel, 0, 0)

# --- MIDDLE VIRTUAL LIST VIEW ---
$listView = New-Object System.Windows.Forms.ListView
$listView.View = [System.Windows.Forms.View]::Details
$listView.FullRowSelect = $true
$listView.GridLines = $true
$listView.Dock = "Fill"
$listView.VirtualMode = $true # HIGH PERFORMANCE VIRTUAL MODE
$listView.Columns.Add("No.", 60)
$listView.Columns.Add("Time", 95)
$listView.Columns.Add("Source IP", 140)
$listView.Columns.Add("Destination IP", 140)
$listView.Columns.Add("Protocol", 80)
$listView.Columns.Add("Length", 65)
$listView.Columns.Add("Info", 380)

# Bind Virtual Events for Rendering
$listView.add_RetrieveVirtualItem({
    param($sender, $e)
    if ($e.ItemIndex -lt $script:packetArray.Count) {
        $pkt = $script:packetArray[$e.ItemIndex]
        $item = New-Object System.Windows.Forms.ListViewItem("$($pkt.Number)")
        $item.SubItems.Add($pkt.Time)
        $item.SubItems.Add($pkt.Source)
        $item.SubItems.Add($pkt.Dest)
        $item.SubItems.Add($pkt.Proto)
        $item.SubItems.Add("$($pkt.Length)")
        $item.SubItems.Add($pkt.Info)
        $e.Item = $item
    }
})

$tableLayout.Controls.Add($listView, 0, 1)

# --- BOTTOM PACKET DETAILS VIEW ---
$txtDetails = New-Object System.Windows.Forms.TextBox
$txtDetails.Multiline = $true
$txtDetails.ReadOnly = $true
$txtDetails.ScrollBars = "Both"
$txtDetails.Dock = "Fill"
$txtDetails.Font = New-Object System.Drawing.Font("Consolas", 9.5)
$txtDetails.Text = "Select a packet to inspect payload details..."

$tableLayout.Controls.Add($txtDetails, 0, 2)

# --- BACKGROUND CAPTURE ENGINE WITH PRE-FILTERING ---
function Start-BackgroundCapture ($ip) {
    $script:runspace = [runspacefactory]::CreateRunspace()
    $script:runspace.Open()
    
    $script:psInstance = [powershell]::Create()
    $script:psInstance.Runspace = $script:runspace
    
    $null = $script:psInstance.AddScript({
        param($queue, $state, $targetIp)
        $socket = $null
        try {
            $socket = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,
                                                           [System.Net.Sockets.SocketType]::Raw,
                                                           [System.Net.Sockets.ProtocolType]::IP)
            $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($targetIp), 0)
            $socket.Bind($endpoint)
            
            $inValue = [byte[]]@(1,0,0,0)
            $outValue = [byte[]]@(0,0,0,0)
            $null = $socket.IOControl([System.Net.Sockets.IOControlCode]::ReceiveAll, $inValue, $outValue)
            
            $buffer = New-Object byte[] 65535
            
            while ($state.Running) {
                if ($socket.Available -gt 0) {
                    $received = $socket.Receive($buffer)
                    if ($received -ge 20) {
                        try {
                            $ihl = ($buffer[0] -band 0x0F) * 4
                            $totalLen = ($buffer[2] -shl 8) + $buffer[3]
                            $protocolNum = $buffer[9]

                            $srcIp = "$($buffer[12]).$($buffer[13]).$($buffer[14]).$($buffer[15])"
                            $dstIp = "$($buffer[16]).$($buffer[17]).$($buffer[18]).$($buffer[19])"

                            $proto = "IP"
                            $infoText = "Len=$totalLen"
                            $srcPort = $null; $dstPort = $null

                            if ($protocolNum -eq 6) {
                                $proto = "TCP"
                                if ($received -ge ($ihl + 4)) {
                                    $srcPort = ($buffer[$ihl] -shl 8) + $buffer[$ihl + 1]
                                    $dstPort = ($buffer[$ihl + 2] -shl 8) + $buffer[$ihl + 3]
                                    if ($srcPort -eq 443 -or $dstPort -eq 443) { $proto = "HTTPS" }
                                    elseif ($srcPort -eq 80 -or $dstPort -eq 80) { $proto = "HTTP" }
                                    $infoText = "Src Port: $srcPort -> Dst Port: $dstPort"
                                }
                            } elseif ($protocolNum -eq 17) {
                                $proto = "UDP"
                                if ($received -ge ($ihl + 4)) {
                                    $srcPort = ($buffer[$ihl] -shl 8) + $buffer[$ihl + 1]
                                    $dstPort = ($buffer[$ihl + 2] -shl 8) + $buffer[$ihl + 3]
                                    if ($srcPort -eq 53 -or $dstPort -eq 53) { $proto = "DNS" }
                                    $infoText = "Src Port: $srcPort -> Dst Port: $dstPort"
                                }
                            } elseif ($protocolNum -eq 1) {
                                $proto = "ICMP"
                                $infoText = "Echo Request/Reply"
                            }

                            $dumpLength = [Math]::Min(96, $received)
                            $hexDump = [System.BitConverter]::ToString($buffer, 0, $dumpLength).Replace("-", " ")
                            
                            $asciiChars = for ($i = 0; $i -lt $dumpLength; $i++) {
                                $b = $buffer[$i]
                                if ($b -ge 32 -and $b -le 126) { [char]$b } else { '.' }
                            }
                            $asciiPreview = -join $asciiChars

                            $detailsText =  "==========================================================`r`n" +
                                            " FRAME DETAILS`r`n" +
                                            "==========================================================`r`n" +
                                            "Length: $totalLen bytes | Protocol: $proto ($protocolNum)`r`n" +
                                            "Source: $srcIp`r`nDestination: $dstIp`r`n"
                            if ($srcPort) { $detailsText += "Ports: $srcPort -> $dstPort`r`n" }
                            $detailsText += "`r`nHEX DUMP:`r`n$hexDump`r`n`r`nASCII PREVIEW:`r`n$asciiPreview"

                            $searchableString = "$srcIp $dstIp $proto $infoText $srcPort $dstPort".ToLower()
                            $currentFilter = $state.Filter

                            # Background Pre-Filtering Evaluation
                            if (-not [string]::IsNullOrEmpty($currentFilter)) {
                                if (-not $searchableString.Contains($currentFilter)) {
                                    continue # Skip if doesn't match filter
                                }
                            }

                            $pktObj = [PSCustomObject]@{
                                Time    = (Get-Date -Format "HH:mm:ss.fff")
                                Source  = $srcIp
                                Dest    = $dstIp
                                Proto   = $proto
                                Length  = $totalLen
                                Info    = $infoText
                                Details = $detailsText
                            }
                            $queue.Enqueue($pktObj)
                        } catch {}
                    }
                } else {
                    [System.Threading.Thread]::Sleep(10)
                }
            }
        } finally {
            if ($socket) { $socket.Close(); $socket.Dispose() }
        }
    }).AddArgument($packetQueue).AddArgument($captureState).AddArgument($ip)
    
    $null = $script:psInstance.BeginInvoke()
}

function Stop-BackgroundCapture {
    $captureState.Running = $false
    if ($script:psInstance) {
        $script:psInstance.Dispose()
        $script:psInstance = $null
    }
    if ($script:runspace) {
        $script:runspace.Close()
        $script:runspace.Dispose()
        $script:runspace = $null
    }
}

# --- UI CONSUMER TIMER (Drains Queue to Virtual Array) ---
$uiTimer = New-Object System.Windows.Forms.Timer
$uiTimer.Interval = 50

$uiTimer.Add_Tick({
    $captureState.Filter = $txtFilter.Text.Trim().ToLower()
    if ($packetQueue.IsEmpty) { return }

    $batchAdded = $false
    while (-not $packetQueue.IsEmpty) {
        $pkt = $null
        if ($packetQueue.TryDequeue([ref]$pkt)) {
            $script:packetCounter++
            $numStr = "$script:packetCounter"

            $packetEntry = [PSCustomObject]@{
                Number = $numStr
                Time   = $pkt.Time
                Source = $pkt.Source
                Dest   = $pkt.Dest
                Proto  = $pkt.Proto
                Length = $pkt.Length
                Info   = $pkt.Info
            }

            $script:packetArray.Add($packetEntry)
            $script:capturedPacketsInfo[$numStr] = $pkt.Details
            $batchAdded = $true

            # Ring Buffer Enforcement (Max 10,000 items in Virtual Mode)
            if ($script:packetArray.Count -gt 10000) {
                $remNum = $script:packetArray[0].Number
                $script:packetArray.RemoveAt(0)
                $script:capturedPacketsInfo.Remove($remNum)
            }
        }
    }

    if ($batchAdded) {
        $listView.VirtualListSize = $script:packetArray.Count
        if ($listView.VirtualListSize -gt 0) {
            $listView.EnsureVisible($listView.VirtualListSize - 1)
        }
    }
    $lblStatus.Text = "Status: Capturing (Virtual Engine) | Total: $($script:packetArray.Count)"
})

# --- EVENT HANDLERS ---
$btnToggle.Add_Click({
    if ($captureState.Running) {
        $uiTimer.Stop()
        Stop-BackgroundCapture
        $btnToggle.Text = "Start Capture"
        $btnToggle.BackColor = [System.Drawing.Color]::LightGreen
        $cmbAdapters.Enabled = $true
        $lblStatus.Text = "Status: Stopped | Total Packets: $($script:packetArray.Count)"
        $lblStatus.ForeColor = [System.Drawing.Color]::Black
    } else {
        if ($cmbAdapters.SelectedItem -match '\((.*?)\)') {
            $selectedIp = $matches[1]
            $captureState.Running = $true
            Start-BackgroundCapture -ip $selectedIp
            $uiTimer.Start()
            
            $btnToggle.Text = "Stop Capture"
            $btnToggle.BackColor = [System.Drawing.Color]::Tomato
            $cmbAdapters.Enabled = $false
            $lblStatus.Text = "Status: Capturing..."
            $lblStatus.ForeColor = [System.Drawing.Color]::Red
        }
    }
})

$btnClear.Add_Click({
    $script:packetArray.Clear()
    $script:capturedPacketsInfo.Clear()
    $script:packetCounter = 0
    $listView.VirtualListSize = 0
    $listView.Invalidate()
    $txtDetails.Text = "Select a packet to inspect payload details..."
    $lblStatus.Text = "Status: Cleared"
})

$btnExport.Add_Click({
    if ($script:packetArray.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No packets to export!", "Export Info", "OK", "Information")
        return
    }
    
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV File (*.csv)|*.csv"
    $saveDialog.FileName = "PacketCapture_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    
    if ($saveDialog.ShowDialog() -eq "OK") {
        $exportData = foreach ($pkt in $script:packetArray) {
            $num = $pkt.Number
            [PSCustomObject]@{
                No          = $num
                Time        = $pkt.Time
                Source      = $pkt.Source
                Destination = $pkt.Dest
                Protocol    = $pkt.Proto
                Length      = $pkt.Length
                Info        = $pkt.Info
                Details     = $script:capturedPacketsInfo["$num"]
            }
        }
        $exportData | Export-Csv -Path $saveDialog.FileName -NoTypeInformation -Encoding UTF8
        [System.Windows.Forms.MessageBox]::Show("Successfully exported $($script:packetArray.Count) packets!", "Export Complete", "OK", "Information")
    }
})

$btnImport.Add_Click({
    if ($captureState.Running) {
        $uiTimer.Stop()
        Stop-BackgroundCapture
        $btnToggle.Text = "Start Capture"
        $btnToggle.BackColor = [System.Drawing.Color]::LightGreen
        $cmbAdapters.Enabled = $true
    }

    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "CSV File (*.csv)|*.csv"
    
    if ($openDialog.ShowDialog() -eq "OK") {
        try {
            $importedData = Import-Csv -Path $openDialog.FileName -Encoding UTF8
            
            $script:packetArray.Clear()
            $script:capturedPacketsInfo.Clear()
            $script:packetCounter = 0

            foreach ($row in $importedData) {
                $script:packetCounter++
                $numStr = "$script:packetCounter"

                $packetEntry = [PSCustomObject]@{
                    Number = $numStr
                    Time   = $row.Time
                    Source = $row.Source
                    Dest   = $row.Destination
                    Proto  = $row.Protocol
                    Length = $row.Length
                    Info   = $row.Info
                }
                $script:packetArray.Add($packetEntry)
                
                if (-not [string]::IsNullOrEmpty($row.Details)) {
                    $script:capturedPacketsInfo[$numStr] = $row.Details
                } else {
                    $script:capturedPacketsInfo[$numStr] = "No payload details recorded."
                }
            }
            
            $listView.VirtualListSize = $script:packetArray.Count
            $listView.Invalidate()
            
            $fileName = [System.IO.Path]::GetFileName($openDialog.FileName)
            $lblStatus.Text = "Status: Loaded '$fileName' ($($script:packetArray.Count) Packets)"
            $lblStatus.ForeColor = [System.Drawing.Color]::Blue
            [System.Windows.Forms.MessageBox]::Show("Successfully loaded packets in Virtual Mode!", "Import Success", "OK", "Information")
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to parse CSV file!", "Import Error", "OK", "Error")
        }
    }
})

$listView.add_SelectedIndexChanged({
    if ($listView.SelectedIndices.Count -eq 1) {
        $index = $listView.SelectedIndices[0]
        if ($index -lt $script:packetArray.Count) {
            $selectedNum = $script:packetArray[$index].Number
            if ($script:capturedPacketsInfo.ContainsKey("$selectedNum")) {
                $txtDetails.Text = $script:capturedPacketsInfo["$selectedNum"]
            }
        }
    }
})

$form.Add_FormClosing({
    $uiTimer.Stop()
    Stop-BackgroundCapture
})

$form.ShowDialog() | Out-Null