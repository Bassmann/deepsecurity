# Export Policy information from Trend Micro using the REST API
# Version 1.0


# Get the base URL and the authentication key
$properties = Get-Content ".\..\properties.json" -Raw | ConvertFrom-Json

$headers = @{
    'api-secret-key' = $properties.secretkey
    'api-version' = 'v1'
}

$Url = $properties.url

# Export the policies including all antimaleware and intrusion prevention settings
$uri = "$url/policies"

"{0} Get Policies" -f (Get-Date -Format u)

$policies = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

$policiesList = @()

foreach ($policy in $policies.policies) {
    $policyInfo = New-Object PSObject
    $policyInfo | Add-Member -type NoteProperty -Name Id -Value $policy.id
    $policyInfo | Add-Member -type NoteProperty -Name Name -Value $policy.name
    $policyInfo | Add-Member -type NoteProperty -Name Description -Value $policy.description
    $policyInfo | Add-Member -type NoteProperty -Name AMStatus -Value $policy.antiMalware.state
    $policyInfo | Add-Member -type NoteProperty -Name AMModuleStatus -Value $policy.antiMalware.moduleStatus.status
    $policyInfo | Add-Member -type NoteProperty -Name AMStatusMessage -Value $policy.antiMalware.moduleStatus.statusMessage
    $policyInfo | Add-Member -type NoteProperty -Name AMManualScanConfigId -Value $policy.antiMalware.manualScanConfigurationID
    $policyInfo | Add-Member -type NoteProperty -Name AMRealtimeScanConfigId -Value $policy.antiMalware.realTimeScanConfigurationID
    $policyInfo | Add-Member -type NoteProperty -Name AMScheduledScanConfigId -Value $policy.antiMalware.scheduledScanConfigurationID
    $policyInfo | Add-Member -type NoteProperty -Name AMRealtimeScanScheduleId -Value $policy.antiMalware.realTimeScanScheduleID
    $policyInfo | Add-Member -type NoteProperty -Name IPStatus -Value $policy.intrusionPrevention.moduleStatus.status
    $policyInfo | Add-Member -type NoteProperty -Name IPStatusMessage -Value $policy.intrusionPrevention.moduleStatus.statusMessage
    $policyInfo | Add-Member -type NoteProperty -Name RecommendationScanmode -Value $policy.recommendationScanMode

    # add all the policysettings for antimalware, intrusionprevention and platform
    $policy.policySettings.PSObject.Properties | Where-object {($_.Name -like "intrusion*") -or ($_.Name -like "antimalware*") -or ($_.name -like "platform*")} | sort | ForEach-Object {
        $name = $_.Name;
        $value = $_.Value.value;
        $policyInfo | Add-Member -type NoteProperty -Name $name -Value $value
    }
            
    $policiesList+= $policyInfo
}

$policiesList | Export-Csv -Path "../output/Policies.csv" -Delimiter ";" -NoTypeInformation
$xlfile = "../output/Policies.xlsx"

$policiesList | Export-Excel -Path "../output/Policies.xlsx" -WorksheetName "Policies" -Title "Policies" -AutoSize

# Export the Antimalware configurations
"{0} Get Antimalware configurations" -f (Get-Date -Format u)

$uri = "$Url/antimalwareconfigurations"
$amconfigs = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

$amconfigs.antiMalwareConfigurations | Export-Csv -Path "../output/AMConfigs.csv" -Delimiter ";" -NoTypeInformation
$amconfigs.antiMalwareConfigurations | Export-Excel -Path $xlfile -WorksheetName "AM Configs" -Title "AMConfigs" -AutoSize

# Export the directory exclusions
"{0} Get Directory exclusions" -f (Get-Date -Format u)

$uri = "$Url/directorylists"
$amdirectories = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

$directoriesList = @()

foreach ($directory in $amdirectories.directoryLists) {
    $dirInfo = New-Object PSObject
    $description = $directory.description -replace "\n"
    $items = $directory.items -join " "

    $dirInfo | Add-Member -type NoteProperty -Name Id -Value $directory.Id 
    $dirInfo | Add-Member -type NoteProperty -Name Name -Value $directory.Name
    $dirInfo | Add-Member -type NoteProperty -Name Description -Value $description
    $dirInfo | Add-Member -type NoteProperty -Name Directories -Value $items

    $directoriesList+= $dirInfo
}

$directoriesList | Export-Csv -Path "../output/DirectoryExclusions.csv" -Delimiter ";" -NoTypeInformation
$directoriesList | Export-Excel -Path $xlfile -WorksheetName "DirExclusions" -Title "Directory Exclusions" -AutoSize

# Export the file list exclusions
"{0} Get file exclusions" -f (Get-Date -Format u)

$uri = "$Url/filelists"
$amfiles = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

$fileList = @()

foreach ($file in $amfiles.fileLists) {
    $fileInfo = New-Object PSObject
    $description = $file.description -replace "\n"
    $items = $file.items -join " "

    $fileInfo | Add-Member -type NoteProperty -Name Id -Value $file.Id 
    $fileInfo | Add-Member -type NoteProperty -Name Name -Value $file.Name
    $fileInfo | Add-Member -type NoteProperty -Name Description -Value $description
    $fileInfo | Add-Member -type NoteProperty -Name Directories -Value $items

    $fileList+= $fileInfo
}

$fileList | Export-Csv -Path "../output/fileExclusions.csv" -Delimiter ";" -NoTypeInformation
$fileList | Export-Excel -Path $xlfile -WorksheetName "File Exclusions" -Title "File Exclusions" -AutoSize

# Export the file extension exclusions
"{0} Get file extension exclusions" -f (Get-Date -Format u)

$uri = "$Url/fileextensionlists"
$amfileextensions = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

$fileExtList = @()

foreach ($fileExt in $amfileextensions.fileExtensionLists) {
    $fileExtInfo = New-Object PSObject
    $description = $fileExt.description -replace "\n"
    $items = $fileExt.items -join " "

    $fileExtInfo | Add-Member -type NoteProperty -Name Id -Value $fileExt.Id 
    $fileExtInfo | Add-Member -type NoteProperty -Name Name -Value $fileExt.Name
    $fileExtInfo | Add-Member -type NoteProperty -Name Description -Value $description
    $fileExtInfo | Add-Member -type NoteProperty -Name Directories -Value $items

    $fileExtList+= $fileExtInfo
}

$fileExtList | Export-Csv -Path "../output/FileExtensionExclusions.csv" -Delimiter ";" -NoTypeInformation
$fileExtList | Export-Excel -Path $xlfile -WorksheetName "File Extension Exclusions" -Title "File Extension Exclusions" -AutoSize