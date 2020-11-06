function Get-IntuneDevicePolicyAssignments {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string] $memUserPrompt,
        [string] $targetDeviceName

    )

    # Environment Prep
    Connect-MSGraph
    Update-MSGraphEnvironment -SchemaVersion beta

    #Variables
    #$polColl = @()
    $polCollCleanup = @()
    $addedGroups = @()
    $multiGroup = @()
    $gMembers = @()
    $gMembership = @()
    $od = '@odata.type'
    $polResults = ""
    $devices = ""
    $deviceAssignments = @{}
    $assignedGroup = @()

    #Variables
    $memUserPrompt = Read-Host -Prompt 'Input Intune-licensed user'

    #Get User/device object
    $sName = Get-AzADUser -DisplayName "$memUserPrompt*"
    Write-Host "$($sName.DisplayName) identified"

    #Return devices associated with user
    $devices = Get-IntuneManagedDevice | Where-Object { $_.userPrincipalName -eq "$($sName.UserPrincipalName)" }

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
                    $ngroups = (Get-AADGroupMember -groupId "$nestedGp").id
                    foreach ($g in $ngroups) {
                        $polColl += @{$id = $g }
                        Write-Host "Adding nestedG $g as individual group for $id"
                    }
                }
                else {
                    # if not a nested group, save to the Policy Collection
                    $polColl += @{$id = $assignedGroup }
                }
            }
            # Split multi-groups into individual GUIDs and add to policy collection
            # $addedGroups += $multiGroup.Split(" ")
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
    #Cleanup returned groups
    $polCollCleanup = $polColl | Select-Object -Unique
    $upolColl = $polCollCleanup | Where-Object { $_.Values -notlike "*null*" }

    #From list of groups targeted with policies, identify those that this device is a member of
    $gMembership = @()
    foreach ($group in ($polColl).values) {
        $gMembers = (Get-AADGroupMember -groupId $group).DeviceId
        #if a group contains the target device, add to an array
        if ( $gMembers -contains $targetDeviceID) {
       
            $gMembership += $group
            Write-Host "Group $group Match" -ForegroundColor Green     
        }
        else {
            Write-Host "Not in group"
        }
    }

    $gMembership = $gMembership | Select-Object -Unique

    # for the groups that this device is a member of (where greater than 0)
    if ($gMembership.Count -gt 0) {
        # identify policies assigned to the device's assigned groups
        foreach ($gr in $gMembership) {
            foreach ($row in $upolColl | Where-Object { $_.Values -contains $gr })
            { $filterPol += $row.Keys }
        }

        # Filter unique
        $filterPol = $filterPol | Select-Object -Unique
        v
        # grab associated policies (Upoll Key ids)    
        Write-Verbose "Filtering policies" -Verbose
        #Write-Host $filterPol
        # Return policies
        foreach ($p in $filterPol) {
            Write-Verbose $polResults.displayName -Verbose
            $polResults = Get-IntuneDeviceConfigurationPolicy | Where-Object { $_.id -eq $p }
            $deviceAssignments.add($($polResults.displayName), $polResults)
        }
        # Results
    }
    else {
        Write-Host "This device does not have assigned configuration policies" -ForegroundColor Yellow
        $deviceAssignments = @{
            "DeviceName" = $targetDeviceName
            "DeviceGUID" = $targetDeviceId
        }
    }
    $result = Write-Output $deviceAssignments -Verbose
}