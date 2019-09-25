# Update description for objects in Trend Micro console. A new line with a date and the new description is added to the existing description
# The objects and the new new descriptions are read from a CSV file
# Version 1.0


# Get the base URL and the authentication key
$properties = Get-Content ".\..\properties.json" -Raw | ConvertFrom-Json

$headers = @{
    'api-secret-key' = $properties.secretkey
    'api-version' = 'v1'
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Url = $properties.url

$systems = import-csv -Path "..\Descriptions.csv" 

$systems | foreach {
    $srv = $_.Server
    $desc = $_.description
    "{0} Setting description $desc for Server $srv" -f (Get-Date -Format u)

    $searchbody = @{
        "searchCriteria"= @{
            "fieldName" = "hostName"
            "stringTest" = "equal"
            "stringValue" = $srv+'%'}
    }

    $json = ConvertTo-Json $searchbody

    $srvuri = "$url/computers/search?expand=none"

    $computer = Invoke-RestMethod -Uri $srvuri -Method Post -Headers $headers -Body $json  -ContentType 'application/json'
    $computer.computers.Count
    $computerid = $computer.computers[0].ID

    $date = Get-Date -Format "yyyy-mm-dd"
    $newdesc = $computer.computers[0].description + "`n$($date): $desc"
    $updatebody = @{
        "description" = $newdesc
        }

    $updatejson = ConvertTo-Json $updatebody
    $updateuri="$url/computers/$computerid"

    $computerupdate = Invoke-RestMethod -Uri $updateuri -Method Post -Headers $headers -Body $updatejson -ContentType 'application/json'
}
    