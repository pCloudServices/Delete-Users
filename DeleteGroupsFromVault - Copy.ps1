param(
    [ValidateScript({
        If(![string]::IsNullOrEmpty($_)) {
            $isValid = ($_ -like "*.privilegecloud.cyberark.com*") -or ($_ -like "*.cyberark.cloud*")
            if (-not $isValid) {
                throw "Invalid URL format. Please specify a valid Privilege Cloud tenant URL (e.g.https://<subdomain>.cyberark.cloud)."
            }
            $true
        }
        Else {
            $true
        }
    })]
    [Parameter(Mandatory = $true, HelpMessage = "Specify the URL of the Privilege Cloud tenant (e.g., https://<subdomain>.cyberark.cloud)")]
    [string]$PortalURL,
    [Parameter(Mandatory = $true, HelpMessage = "Specify a User that has permissions in both Identity User Management and Vault Audit User. (e.g. mike@cyberark.cloud.1022")]
    [PSCredential]$Credentials
)


# Modules
$mainModule = "Import_AllModules.psm1"

$modulePaths = @(
"..\\PS-Modules\\$mainModule",
"..\\..\\PS-Modules\\$mainModule",
".\\PS-Modules\\$mainModule", 
".\\$mainModule"
"..\\$mainModule"
".\\..\\$mainModule"
"..\\..\\$mainModule"
)

foreach ($modulePath in $modulePaths) {

    if (Test-Path $modulePath) {
        try {
            Import-Module $modulePath -ErrorAction Stop -DisableNameChecking -Force
        } catch {
            Write-Host "Failed to import module from $modulePath. Error: $_"
            Write-Host "check that you copied the PS-Modules folder correctly."
            Pause
            Exit
        }
     }
}

$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
$global:LOG_FILE_PATH = "$ScriptLocation\_DeleteUsersFromVault.log"
$global:ConfirmedDeleted = "$ScriptLocation\Confirmed_Deleted_Users.txt"
$global:FailedToDelete = "$ScriptLocation\Failed_Delete.txt"
$global:UsersNotFound = "$ScriptLocation\Users_Not_Found.txt"

[int]$scriptVersion = 5

# PS Window title
$Host.UI.RawUI.WindowTitle = "Privilege Cloud Delete Users Script"

## Force Output to be UTF8 (for OS with different languages)
$OutputEncoding = [Console]::InputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding

# Prep Files
Try{
    Remove-Item $ConfirmedDeleted -Force -ErrorAction SilentlyContinue
    Remove-Item $FailedToDelete -Force -ErrorAction SilentlyContinue
    Remove-Item $UsersNotFound -Force -ErrorAction SilentlyContinue
}Catch{}


function Add-TimestampToPath {
    param (
        [String]$Path,
        [String]$Timestamp
    )
    $directory = Split-Path -Parent $Path
    $filename = Split-Path -Leaf $Path
    return "$directory\$Timestamp-$filename"
}


# Start Script here

#Cleanup log file if it gets too big
if (Test-Path $LOG_FILE_PATH)
{
    if (Get-ChildItem $LOG_FILE_PATH -File | Where-Object { $_.Length -gt 5000KB })
    {
        Write-LogMessage -type Info -MSG "Log file is getting too big, deleting it." -early
        Remove-Item $LOG_FILE_PATH -Force
    }
}

# Build Urls
$platformURLs = DetermineTenantTypeURLs -PortalURL $PortalURL
$IdentityAPIURL = $platformURLs.IdentityURL
$pvwaAPI = $platformURLs.PVWA_API_URLs.PVWAAPI
$VaultURL = $platformURLs.vaultURL    

# Privilege Cloud API
$script:PVWA_GetallUsers = "$pvwaAPI/UserGroups"
$script:PVWA_GetUser = "$pvwaAPI/UserGroups/{0}/"

# Login
Refresh-Token -PlatformURLs $platformURLs -creds $Credentials -ForceAuthType $ForceAuthType

Write-LogMessage -type Info -MSG "Checking if we have sufficient permissions to peform the query in Privilege Cloud..." -Early
$PrivilegeCloudPermission=$(Get-VaultPermissions -URLAPI $pvwaAPI -logonHeader $logonheader -pvwaUser $Credentials.UserName)
if ($PrivilegeCloudPermission -match "AddUpdateUsers"){
    Write-LogMessage -type Success -MSG "Passed minimal permissions requirement to perform query in Privilege Cloud"
}
Else{
    Write-LogMessage -type Error -MSG "User doesn't have sufficient permissions in Privilege Cloud, make sure user has Vault Authorization `"AddUpdateUsers`" permission."
    Write-Host "Displaying Current permissions:" -ForegroundColor Yellow
    $PrivilegeCloudPermission
    Pause
    Exit
}


# Delete Action

Try{
    # Get Users from Vault
    $VaultUsersToDeleteFile = gc $(Get-UserFile)
    
    # Display warning messages
    Write-LogMessage -type Info -MSG "Listing $($VaultUsersToDeleteFile.count) user/s that are about to be deleted." -Early
    $VaultUsersToDeleteFile
    Write-LogMessage -type Warning -MSG "Check the list and press ENTER to proceed."
    Pause
    
    $lastWarningCount = Get-Choice -Title "Are you sure you want to delete ($($VaultUsersToDeleteFile.count)) User/s? " -Options "Yes", "No" -DefaultChoice 1
    if ($lastWarningCount -eq "No")
    {
        Write-LogMessage -type info -MSG "Chosen No, aborting..." -early
        Pause
        Exit
    }
    
    
    Try{
        Write-LogMessage -type Info -MSG "Deleting $($VaultUsersToDeleteFile.count) User/s"

        # Init counter
        [int]$counter = 1 

        # Init timestamp
        $dateString = Get-Date -Format "yyyyMMdd-HHmm"

        # Init filenames with timestamp
        $ConfirmedDeleted = Add-TimestampToPath -Path $ConfirmedDeleted -Timestamp $dateString
        $FailedToDelete = Add-TimestampToPath -Path $FailedToDelete -Timestamp $dateString
        $UsersNotFound = Add-TimestampToPath -Path $UsersNotFound -Timestamp $dateString


        foreach ($user in $VaultUsersToDeleteFile){
            Refresh-Token -PlatformURLs $platformURLs -creds $Credentials -ForceAuthType $ForceAuthType

            Write-LogMessage -type info -MSG "Getting details for Group: $($user)" -Early
            # Get user details
            $UserDetails = Invoke-RestMethod -Uri ("$PVWA_GetallUsers"+"?filter=Groupname eq $($user)") -Method Get -ContentType "application/json" -Headers $logonheader -ErrorVariable pvwaERR
            $Exact = $UserDetails.value | Where-Object { $_.GroupName -eq $user }
            Write-LogMessage -type info -MSG "Group id is: $($Exact.id)" -early
            if ($Exact -eq $null) {
                Write-LogMessage -type Error -MSG "Couldn't find user $($user), deleted or doesn't exist? skipping..."
                $user | out-file $UsersNotFound -Append
                # If we can't find user skip to next user.
                Continue
            }
            
            # Delete User
            Write-LogMessage -type Info -MSG "Deleting Group $($exact.GroupName)" -early
            $respDelete = Invoke-RestMethod -Uri $($PVWA_GetUser -f $($Exact.id)) -Method Delete -Headers $logonheader -ErrorVariable pvwaERR
            
            # Confirm Delete
            Write-LogMessage -type Info -Msg "Confirming Group was deleted by getting Group details" -early
            $UserDetails = Invoke-RestMethod -Uri ("$PVWA_GetallUsers"+"?filter=Groupname eq $($user)") -Method Get -ContentType "application/json" -Headers $logonheader -ErrorVariable pvwaERR
            $Exact = $UserDetails.value | Where-Object { $_.GroupName -eq $user }
            if($Exact -eq $null){
                Write-LogMessage -type Success -MSG "[$($counter)/$($VaultUsersToDeleteFile.count)] Successfully deleted user: $($user)"
                # Save to file
                $user | out-file $ConfirmedDeleted -Append
                # Inc counter
                $counter += 1

            }
            Else{
                Write-LogMessage -type Error -Msg "Unable to delete Group: $user ERROR: $UserDetails"
                $user | out-file $FailedToDelete -Append
            }
        }
            Write-LogMessage -type Info -Msg "Finished running script." -Early
    }
    Catch
	   {
            Write-LogMessage -type Error -MSG "Couldn't delete user: $user ..."
            Write-LogMessage -type Error -Msg "Error: $(Collect-ExceptionMessage $_.exception.message $($_.ErrorDetails.Message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri) $pvwaERR)"
            $user | out-file $FailedToDelete -Append
	   }
    
}Catch{
    Write-LogMessage -Type Error -Msg "Error: $($_.exception.message) $($_.ErrorDetails.Message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri) $pvwaERR)"
    Write-LogMessage -Type Error -Msg "Error: $(Collect-ExceptionMessage $_.Exception)"

}