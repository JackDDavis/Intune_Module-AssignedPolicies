<#
 .Synopsis
  Output user's policy

 .Description
  For a particular user's device, retrieve the specific policies that are targeted

 .Parameter UPN
  Target user's SAN or UPN name

 .Parameter targetDeviceName
  Target User's device

 .Parameter outputPath
  Path for File Output

 .Example
  Get-IntuneDevicePolicyAssignments -UPN 'Jack' -targetDeviceName 'computer1' -outputPath "$outPath\testfile.txt"
#>
function Get-IntuneDevicePolicyAssignments {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string] $UPN,

        [Parameter()]
        [string] $TargetDeviceName,

        [Parameter()]
        [System.IO.FileInfo] $OutputPath
    )

    # Environment Prep
    Connect-MSGraph
    Update-MSGraphEnvironment -SchemaVersion beta

    # Declare Variables
    $addedGroups = @()
    $assignedGroupId = @()
    $devices = ""
    $deviceAssignments = @{}
    $dAssignId = @{}
    $filterPol = @()
    $gMembers = @()
    $gMembership = @()
    $nestedGp = @()
    $od = '@odata.type'
    $odType = '#microsoft.graph.device'
    $policyResults = ""
    $polCollection = @()
    $modReady = $true
    
    try {
        $aadUsers = Get-AzureADUser
    }
    catch {
        "Please run Connect-AzureAD before running"
        $modReady = $false
    }

    if ($modReady) {
        #Get User object
        $sName = $aadUsers | Where-Object { $_.UserPrincipalName -eq "$UPN" }
        Write-Host "$($sName.DisplayName) identified"
        
        if (-not($null -eq $TargetDeviceName)) {
            Write-Verbose "device already input as param" -Verbose
            $devices = Get-IntuneManagedDevice | Where-Object {$_.deviceName -like $TargetDeviceName}
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
            $dAssignId.Add("DeviceName", $targetDeviceName)
            $dAssignId.Add("DeviceGUID", $targetDeviceId)
        }
        else {
            $targetDevice = $devices | Where-Object { $_.deviceName -eq $targetDeviceName }
            $targetDeviceId = ($targetDevice).azureADDeviceId
            #Assign device info to Output
            $deviceAssignments.Add("DeviceName", $targetDeviceName)
            $deviceAssignments.Add("DeviceGUID", $targetDeviceId)
            $dAssignId.Add("DeviceName", $targetDeviceName)
            $dAssignId.Add("DeviceGUID", $targetDeviceId)
        }

        # Return all configured policies
        Write-Verbose "Querying Configuration Policies" -Verbose
        $memPolicies = Get-IntuneDeviceConfigurationPolicy
        $configId = $memPolicies.id

        # Identify target group(s) for each policy id assignment
        Write-Verbose "Querying available groups" -Verbose
        foreach ($id in $configId) {
            #Return the assigned group
            $assignedGroupId = ((Get-IntuneDeviceConfigurationPolicyAssignment -deviceConfigurationId $id).target).groupId
            # Check to see if the returned assigned group is empty or not
            if ($null -ne $assignedGroupId) {
                # if it is assigned to more than 1 group, 
                #identify nested groups
                if ($assignedGroupId.Count -gt 1) {
                    #Check if it is a device group &, if so, break out the nested group
                    foreach ($i in $assignedGroupId) {
                        #Pull the type of group (User or Device) to ensure it's a device type
                        $gTypeVerify = (Get-AADGroupMember -groupId "$i").$od | Select-Object -Unique
                        #if it is a Device group & not empty, add it to 
                        if (!($gTypeVerify -eq $odType) -and ($null -ne $gTypeVerify)) {
                            $nestedGp += $assignedGroupId
                            $ngroups = (Get-AADGroupMember -groupId $nestedGp).id
                        }
                
                
                        foreach ($g in $ngroups) {
                            $GroupMembers2 = (Get-AzureADGroupMember -ObjectId $g).DeviceId
                            if ($GroupMembers2 -contains $targetDeviceId) {
                                $polCollection += @{$id = $g }
                                Write-Verbose "Adding nested group $g as an individual group against policy id $id" -Verbose    
                            }
                        }
                    }
                }
                # if policy id assignment is 1:1, add to Policy Collection
                else {
                    # if not a nested group, & matches a group that includes the device then save to the Policy Collection
                    $GroupMembers = (Get-AzureADGroupMember -ObjectId $assignedGroupId).DeviceId
                    if ($GroupMembers -contains $targetDeviceId) {
                        $polCollection += @{$id = $assignedGroupId }
                    }
                }
            }
            else {
                #if it isn't a targeted group for the policy, do the following
                $failedPol = Get-IntuneDeviceConfigurationPolicy -deviceConfigurationId $id
                $failedOd = "@odata.type"
                $targetAllDvc = (Get-IntuneDeviceConfigurationPolicyAssignment -deviceConfigurationId $id).target.$failedOd
                #Write-Verbose "No individual target groups identified for policy: $($failedPol.displayname)" -Verbose
                if ($targetAllDvc -eq "#microsoft.graph.allDevicesAssignmentTarget") {
                    Write-Verbose "$($failedPol.displayName) is assigned to all Users or Devices" -Verbose
                    $idName = $failedPol.displayName
                    $deviceAssignments.Add($idName, $failedPol)
                    $dAssignId.Add($idName, $failedPol.id)
        
                }        
            }
        }

        # Add multi-group policy assignments to Policy Collection as 1:1 pairing
        foreach ($mg in $addedGroups) {
            $polCollection += @{$id = $mg }
        }

        # From list of groups targeted with policies, identify those that this device is a member of
        $gMembership = @()
        foreach ($group in $polCollection.values) {
            $gMembers = (Get-AADGroupMember -groupId $group).DeviceId
            # if a group contains the target device, add to an array
            if ( $gMembers -contains $targetDeviceID) {
       
                $gMembership += $group
                #Write-Host "Group $group Match" -ForegroundColor Green     
            }
        }
        if ($null -eq $gMembership) {
            Write-Verbose "No assigned policies identified for $targetDeviceName ($)" -Verbose
        }
        else {
            $gMembership = $gMembership | Select-Object -Unique
        }

        # for the groups that this device is a member of (where greater than 0)
        if ($gMembership.Count -gt 0) {
            # identify policies assigned to the device's assigned groups
            foreach ($gr in $gMembership) {
                foreach ($item in $polCollection | Where-Object { $_.Values -contains $gr }) {
                    $filterPol += $item.Keys 
                    #Write-Host $item.Keys
                }
            }

            # Filter unique
            Write-Verbose "Filtering $($filterPol.count) policies" -Verbose  
            #$filterPol = $filterPol | Select-Object -Unique
            # Return policies
            foreach ($p in $filterPol) {
                $policyResults = Get-IntuneDeviceConfigurationPolicy | Where-Object { $_.id -eq $p }
                Write-Verbose $policyResults.displayName -Verbose
                $deviceAssignments.add($($policyResults.displayName), $policyResults)
                $dAssignId.Add($($policyResults.displayName), $p)
            }
        }
        else {
            Write-Verbose "$targetDeviceName ($targetDeviceId) does not have assigned device configuration policies" -Verbose
            $deviceAssignments = @{
                "DeviceName" = $targetDeviceName
                "DeviceGUID" = $targetDeviceId
            }
            $dAssignId = @{
                "DeviceName" = $targetDeviceName
                "DeviceGUID" = $targetDeviceId
            }
        }

        $results = $dAssignId

        #Return $dAssignId
        if ($outputPath) {
            #$results | Select-Object -ExpandProperty Values | Out-File -FilePath $outputPath
            $results | Out-File -FilePath $outputPath

        }    
    }
}
Export-ModuleMember -Function 'Get-IntuneDevicePolicyAssignments'