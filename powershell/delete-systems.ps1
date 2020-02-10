# Delete objects in Trend Micro console that no longer exist in the environment.
# The objects are read from a CSV file
# Version 1.0


# Get the base URL and the authentication key
$properties = Get-Content ".\..\properties.json" -Raw | ConvertFrom-Json

$headers = @{
    'api-secret-key' = $properties.secretkey
    'api-version' = 'v1'
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Url = $properties.url

$systems = import-csv -Path "..\TMCleanUp_to be deleted.csv"
$output = @()
$thisyear = Get-Date -Year (Get-Date).Year -Month 1 -Day 1 -Hour 0 -Minute 0

$systems | foreach {
    $outcome = ""
    $srv = $_.FullName
    "{0} Deleting server $srv" -f (Get-Date -Format u)

    $searchbody = @{
        "searchCriteria"= @{
            "fieldName" = "hostName"
            "stringTest" = "equal"
            "stringValue" = $srv+'%'}
    }

    $json = ConvertTo-Json $searchbody

    $srvuri = "$url/computers/search?expand=none"

    $computer = Invoke-RestMethod -Uri $srvuri -Method Post -Headers $headers -Body $json  -ContentType 'application/json'

    if ($computer.computers.Count -eq 0) {
        $outcome = "Doesn't exist anymore" }
    elseif ($computer.computers.Count -gt 1) {
        $outcome = "Exists more than once"
    } else {
        $computerid = $computer.computers[0].ID
        $lastcommunication = Get-Date ((Get-Date 01.01.1970)+([System.TimeSpan]::frommilliseconds($computer.computers[0].lastAgentCommunication)))

        if ($lastcommunication -lt $thisyear) {

            $deleteuri="$url/computers/$computerid"

            Invoke-RestMethod -Uri $deleteuri -Method Delete -Headers $headers -ContentType 'application/json'

            $outcome = "Deleted"
        } else {
            $outcome = "Not Deleted too recent communication at $lastcommunication"
        }
    }

    $new = $_
    $new | Add-Member -type NoteProperty -Name Result -Value $outcome
    $output += $new
}

$output | export-csv -Path "..\output\DS_Deleted.csv" -NoTypeInformation
