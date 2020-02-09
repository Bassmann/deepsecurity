# Export Policy information from Trend Micro using the REST API
# Limit output to interesting data
# Version 1.0


# Get the base URL and the authentication key
$properties = Get-Content ".\..\properties.json" -Raw | ConvertFrom-Json

$headers = @{
    'api-secret-key' = $properties.secretkey
    'api-version' = 'v1'
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Url = $properties.url

# Export the Antimalware configurations
"{0} Get Antimalware configurations" -f (Get-Date -Format u)

$uri = "$Url/antimalwareconfigurations"
$amconfigs = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

# Export the directory exclusions
"{0} Get Directory exclusions" -f (Get-Date -Format u)

$uri = "$Url/directorylists"
$amdirectories = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

 # Export the file list exclusions
 "{0} Get file exclusions" -f (Get-Date -Format u)

 $uri = "$Url/filelists"
 $amfiles = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

# Export the file extension exclusions
"{0} Get file extension exclusions" -f (Get-Date -Format u)

$uri = "$Url/fileextensionlists"
$amfileextensions = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

# Export the policies including all antimaleware and intrusion prevention settings
$uri = "$url/policies"

"{0} Get Policies" -f (Get-Date -Format u)

$policies = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

"{0} Preparing Output" -f (Get-Date -Format u)
$policiesList = @()

foreach ($policy in $policies.policies) {
    $policyInfo = New-Object PSObject
    $policyInfo | Add-Member -type NoteProperty -Name Id -Value $policy.id
    $policyInfo | Add-Member -type NoteProperty -Name Name -Value $policy.name
    $policyInfo | Add-Member -type NoteProperty -Name Description -Value $policy.description
    $policyInfo | Add-Member -type NoteProperty -Name antiMalwareStatus -Value $policy.antiMalware.state
    $policyInfo | Add-Member -type NoteProperty -Name antiMalwareModuleStatus -Value $policy.antiMalware.moduleStatus.status
    $policyInfo | Add-Member -type NoteProperty -Name antiMalwareStatusMessage -Value $policy.antiMalware.moduleStatus.statusMessage

    $scanconfig = $amconfigs.antiMalwareConfigurations | Where-Object {$_.ID -eq $policy.antiMalware.realTimeScanConfigurationID}
    $direxclusion = $amdirectories.directoryLists | Where-Object {$_.Id -eq $scanconfig.excludedDirectoryListID}
    $fileexclusion = $amfiles.fileLists | Where-Object {$_.ID -eq $scanconfig.excludedFileListID}
    $fileextexclusion = $amfileextensions.fileExtensionLists | Where-Object {$_.ID -eq $scanconfig.excludedFileExtensionListID}

    $excludeddirs = $direxclusion.items -join " "
    $excludedfiles = $fileexclusion.items -join " "
    $excludedext = $fileextexclusion.items -join " "

    $policyInfo | Add-Member -type NoteProperty -Name antiMalwareExcludedDirectories -Value $excludeddirs
    $policyInfo | Add-Member -type NoteProperty -Name antiMalwareExcludedFiles -Value $excludedfiles
    $policyInfo | Add-Member -type NoteProperty -Name antiMalwareExcludedFileExtensions -Value $excludedext

    # add all the settings for antimalwareConfiguration
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigalertEnabled -Value $scanconfig.alertEnabled
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigbehaviorMonitoringEnabled -Value $scanconfig.behaviorMonitoringEnabled
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigcustomRemediationActionsEnabled -Value $scanconfig.customRemediationActionsEnabled
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigdocumentExploitProtectionEnabled -Value $scanconfig.documentExploitProtectionEnabled
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigintelliTrapEnabled -Value $scanconfig.intelliTrapEnabled
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigmachineLearningEnabled -Value $scanconfig.machineLearningEnabled
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigmemoryScanEnabled -Value $scanconfig.memoryScanEnabled
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigmicrosoftOfficeEnabled -Value $scanconfig.microsoftOfficeEnabled
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfignetworkDirectoriesEnabled -Value $scanconfig.networkDirectoriesEnabled
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigscanCompressedEnabled -Value $scanconfig.scanCompressedEnabled
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigspywareEnabled -Value $scanconfig.spywareEnabled
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigmicrosoftOfficeLayers -Value $scanconfig.microsoftOfficeLayers
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigscanCompressedMaximumFiles -Value $scanconfig.scanCompressedMaximumFiles
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigscanCompressedMaximumLevels -Value $scanconfig.scanCompressedMaximumLevels
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigscanCompressedMaximumSize -Value $scanconfig.scanCompressedMaximumSize
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigdirectoriesToScan -Value $scanconfig.directoriesToScan
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigdocumentExploitHeuristicLevel -Value $scanconfig.documentExploitHeuristicLevel
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigdocumentExploitProtection -Value $scanconfig.documentExploitProtection
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigfilesToScan -Value $scanconfig.filesToScan
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigrealTimeScan -Value $scanconfig.realTimeScan
    $policyInfo | Add-Member -type NoteProperty -Name antimalwareConfigscanType -Value $scanconfig.scanType

    # add all the policysettings for antimalware
    $policy.policySettings.PSObject.Properties | Where-object {$_.Name -like "antimalware*"} | Sort-Object | ForEach-Object {
        $name = $_.Name;
        $value = $_.Value.value;
        $policyInfo | Add-Member -type NoteProperty -Name $name -Value $value
    }

    $policyInfo | Add-Member -type NoteProperty -Name intrusionPreventionStatus -Value $policy.intrusionPrevention.moduleStatus.status
    $policyInfo | Add-Member -type NoteProperty -Name intrusionPreventionStatusMessage -Value $policy.intrusionPrevention.moduleStatus.statusMessage
    $policyInfo | Add-Member -type NoteProperty -Name intrusionPreventionRecommendationScanmode -Value $policy.recommendationScanMode

    # add all the policysettings for intrusionprevention
    $policy.policySettings.PSObject.Properties | Where-object {$_.Name -like "intrusion*"} | Sort-Object | ForEach-Object {
        $name = $_.Name;
        $value = $_.Value.value;
        $policyInfo | Add-Member -type NoteProperty -Name $name -Value $value
    }

    $policiesList+= $policyInfo
}

"{0} Writing Output" -f (Get-Date -Format u)
$policiesList | Export-Csv -Path "../output/Policies.csv" -Delimiter ";" -NoTypeInformation

# Export to Excel
$xlfile = "../output/Policies-Simple.xlsx"

$expdata = @()
$newdate = (get-date)
$xlexists = Test-Path -Path $xlfile -PathType Leaf

if ($xlexists) {
    $data = Import-Excel -Path $xlfile -WorksheetName "Version"
    $expdata+=$data
    # Assume Version numbers look like Va.b; the new verison will be Va.(b+1)
    $data[-1].Version -match "(V[^.]).(.+)" | out-null
    $version = $matches[1].ToString()
    $newversionnumber = ++([int]$matches[2])
    $newversion = "$version.$newversionnumber"
} else {
    $newversion = 'V1.0'
}

$newinfo = New-Object PSObject
$newinfo | Add-Member -type NoteProperty -Name Version -Value $newversion
$newinfo | Add-Member -type NoteProperty -Name Exported -Value $newdate
$expdata+= $newinfo

Remove-Item $xlfile -ErrorAction Ignore
$expdata | Export-Excel $xlfile -WorkSheetname "Version" -AutoSize

$policiesList | Export-Excel -Path $xlfile -WorksheetName "Policies" -AutoSize -AutoFilter -BoldTopRow
