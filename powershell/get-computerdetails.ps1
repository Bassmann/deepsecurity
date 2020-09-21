# Get the base URL and the authentication key
$properties = Get-Content ".\..\properties.json" -Raw | ConvertFrom-Json

$headers = @{
    'api-secret-key' = $properties.secretkey
    'api-version' = 'v1'
}

$Url = $properties.url
$cmp = @()

$srvuri = "$url/computers/?expand=computerStatus"

$computer = Invoke-RestMethod -Uri $srvuri -Method Get -Headers $headers 

foreach ($srv in $computer.computers) {
    $computerInfo = New-Object PSObject
    $msg = $srv.computerStatus.agentstatusMessages -join ";"

    $computerInfo | Add-Member -type NoteProperty -Name Name -Value $srv.hostName
    $computerInfo | Add-Member -type NoteProperty -Name Status -Value $srv.computerStatus.agentStatus
    $computerInfo | Add-Member -type NoteProperty -Name Messages -Value $msg

    $cmp+=$computerInfo
}

$cmp | export-csv -Path '..\output\ComputerInfos.csv' -NoTypeInformation