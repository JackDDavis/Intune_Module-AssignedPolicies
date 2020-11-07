<#
 .Synopsis
  Output user's policy

 .Description
  For a particular user's device, retrieve the specific policies that are targeted

 .Parameter memUserPrompt
  Target user

 .Parameter targetDeviceName
  Target User's device

 .Parameter outputPath
  Path for File Output

 .Example
  Get-IntuneDevicePolicyAssignments -memUserPrompt 'Jack' -outputPath "$outPath\testfile.txt"
#>
function Get-IntuneDevicePolicyAssignments {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string] $memUserPrompt,
        [string] $targetDeviceName,
        [string] $outputPath
    )

    # Environment Prep
    Connect-MSGraph
    Update-MSGraphEnvironment -SchemaVersion beta

    # Declare Variables
    $polColl = @()
    $addedGroups = @()
    $multiGroup = @()
    $gMembers = @()
    $gMembership = @()
    $od = '@odata.type'
    $polResults = ""
    $devices = ""
    $deviceAssignments = @{}
    $assignedGroup = @()
    $filterPol = @()

    #Get User object
    $sName = Get-AzADUser -DisplayName "$memUserPrompt*"
    Write-Host "$($sName.DisplayName) identified"
        
    if (!($null -eq $targetdevice)) {
        Write-Verbose "device already input as param"
    }
    else {
        #Return devices associated with user
        $devices = Get-IntuneManagedDevice | Where-Object { $_.userPrincipalName -eq "$($sName.UserPrincipalName)" }
    }

    #Select device from list if multiple are currently managed
    if (($devices.id).count -gt 1) {
        Write-Host "There are multiple managed devices enrolled for $($sName.DisplayName). Please specify device." -ForegroundColor Red
        $devices.deviceName
        $targetDeviceName = Read-Host "Provide Devicename from list above"
        $targetDevice = $devices | Where-Object { $_.deviceName -like "$targetDeviceName" }
        $targetDeviceId = ($targetDevice).azureADDeviceId
        #Assign device info to Output
        $deviceAssignments.Add("DeviceName", $targetDeviceName)
        $deviceAssignments.Add("DeviceGUID", $targetDeviceId)
    }
    else {
        $targetDevice = $devices | Where-Object { $_.deviceName -eq $targetDeviceName }
    }

    # Return all configured policies
    Write-Verbose "Querying Configuration Policies" -Verbose
    $memPolicies = Get-IntuneDeviceConfigurationPolicy
    $configId = $memPolicies.id

    # Identify target group(s) for each policy id assignment
    Write-Verbose "Querying available groups" -Verbose
    foreach ($id in $configId) {
        #Return the assigned groups
        $assignedGroup = ((Get-IntuneDeviceConfigurationPolicyAssignment -deviceConfigurationId $id).target).groupId
        # Check to see if the returned assigned group is empty or not
        if ($null -ne $assignedGroup) {
            # if id is assigned to more than 1 group, add to multigroup array
            if ($assignedGroup.Count -gt 1) {
                $multiGroup = $assignedGroup
                Write-Host "$multiGroup" -ForegroundColor Yellow
            }
            # if policy id assignment 1:1, check for nested groups
            else {
                #identify nested groups
                $gTypeVerify = (Get-AADGroupMember -groupId "$assignedGroup").$od | Select-Object -Unique
                if (!($gTypeVerify -eq '#microsoft.graph.device') -and ($null -ne $gTypeVerify)) {
                    $nestedGp += $assignedGroup
                    $ngroups = (Get-AADGroupMember -groupId $nestedGp).id
                    foreach ($g in $ngroups) {
                        $polColl += @{$id = $g }
                        Write-Verbose "Adding nested group $g as an individual group against policy id $id" -Verbose
                    }
                }
                else {
                    # if not a nested group, save to the Policy Collection
                    $polColl += @{$id = $assignedGroup }
                }
            }
        }
        else {
            $failedPol = Get-IntuneDeviceConfigurationPolicy -deviceConfigurationId $id
            $failedOd = "@odata.type"
            $targetAllDvc = (Get-IntuneDeviceConfigurationPolicyAssignment -deviceConfigurationId $id).target.$failedOd
            Write-Verbose "No individual target groups identified for policy: $($failedPol.displayname)" -Verbose
            if ($targetAllDvc -eq "#microsoft.graph.allDevicesAssignmentTarget") {
                Write-Host "$($failedPol.displayName) Assigned to all Users or Devices" -ForegroundColor Yellow
                $idName = $id.displayName
                $deviceAssignments.Add($idName, $failedPol)
            }        
        }
    }
    else {
        Write-Host "Config ID is $id"
    }

    # Add multi-group collections to Policy Collection as 1:1 pairing
    foreach ($mg in $addedGroups) {
        $polColl += @{$id = $mg }
    }

    # From list of groups targeted with policies, identify those that this device is a member of
    $gMembership = @()
    foreach ($group in $polColl.values) {
        $gMembers = (Get-AADGroupMember -groupId $group).DeviceId
        # if a group contains the target device, add to an array
        if ( $gMembers -contains $targetDeviceID) {
       
            $gMembership += $group
            #Write-Host "Group $group Match" -ForegroundColor Green     
        }
    }
    if ($null -eq $gMembership) {
        Write-Host "No assigned policies identified" -ForegroundColor Yellow        
    }
    else {
        $gMembership = $gMembership | Select-Object -Unique
    }

    # for the groups that this device is a member of (where greater than 0)
    if ($gMembership.Count -gt 0) {
        # identify policies assigned to the device's assigned groups
        foreach ($gr in $gMembership) {
            foreach ($item in $polColl | Where-Object { $_.Values -contains $gr })
            { $filterPol += $item.Keys 
            Write-Host $item.Keys}
        }

        # Filter unique
        Write-Verbose "Filtering $($filterPol.count) policies" -Verbose  
        #$filterPol = $filterPol | Select-Object -Unique
        # Return policies
        foreach ($p in $filterPol) {
            $polResults = Get-IntuneDeviceConfigurationPolicy | Where-Object { $_.id -eq $p }
            Write-Verbose $polResults.displayName -Verbose
            $deviceAssignments.add($($polResults.displayName), $polResults)
        }
        # Results
    }
    else {
        Write-Host "This device does not have assigned device configuration policies" -ForegroundColor Yellow
        $deviceAssignments = @{
            "DeviceName" = $targetDeviceName
            "DeviceGUID" = $targetDeviceId
        }
    }

    $results = $deviceAssignments

    Write-Output $deviceAssignments -Verbose
    if ($outputPath) {
        $results | Select-Object -ExpandProperty Values | Out-File -FilePath $outputPath
    }
}
Export-ModuleMember -Function Get-IntuneDeviceConfigurationPolicyAssignment