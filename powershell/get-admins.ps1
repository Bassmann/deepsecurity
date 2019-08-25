# Export admin information from Trend Micro using the REST API
# Version 1.0


# Get the base URL and the authentication key
$properties = Get-Content ".\..\properties.json" | ConvertFrom-Json

$headers = @{
    'api-secret-key' = $properties.secretkey
    'api-version' = 'v1'
}

$Url = $properties.url

# Export the admins including their roles
$adminuri = "$url/administrators"
$rolesuri = "$url/roles"

"{0} Get Admins" -f (Get-Date -Format u)

$admins = Invoke-RestMethod -Uri $adminuri -Method Get -Headers $headers

"{0} Get Roles" -f (Get-Date -Format u)

$roles = Invoke-RestMethod -Uri $rolesuri -Method Get -Headers $headers

$rolesdict = @{}
$roles.roles | ForEach-Object {$rolesdict[$_.id]=$_.name}

$adminList = @()

foreach ($admin in $admins.administrators) {
    $adminInfo = New-Object PSObject
    $role = $rolesdict[$admin.roleId]
    $created = Get-Date ((Get-Date 01.01.1970)+([System.TimeSpan]::frommilliseconds($admin.created))) -format u
    $lastsignin = Get-Date ((Get-Date 01.01.1970)+([System.TimeSpan]::frommilliseconds($admin.lastsignin))) -format u

    $adminInfo | Add-Member -type NoteProperty -Name Username -Value $admin.username
    $adminInfo | Add-Member -type NoteProperty -Name Active -Value $admin.active
    $adminInfo | Add-Member -type NoteProperty -Name External -Value $admin.external
    $adminInfo | Add-Member -type NoteProperty -Name Role -Value $role
    $adminInfo | Add-Member -type NoteProperty -Name Created -Value $created
    $adminInfo | Add-Member -type NoteProperty -Name LastSignIn -Value $lastsignin

    $adminList+= $adminInfo
}

$adminList | Export-Csv -Path "..\output\admins.csv" -Delimiter ";" -NoTypeInformation