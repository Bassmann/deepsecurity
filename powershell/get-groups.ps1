$properties = Get-Content ".\..\properties.json" -Raw | ConvertFrom-Json

$headers = @{
    'api-secret-key' = $properties.secretkey
    'api-version' = 'v1'
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Url = $properties.url

# Export the policies including all antimaleware and intrusion prevention settings
$uri = "$url/computergroups"

"{0} Get Groups" -f (Get-Date -Format u)

$groups = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
