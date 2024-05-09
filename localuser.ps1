# Define the number of days of inactivity before disabling
$InactiveDays = 30

# Get the current date
$Today = Get-Date

# Get all user accounts
$Users = Get-LocalUser

# Loop through each user
foreach ($User in $Users) {
    # Get the last logon time for the user
    $LastLogon = $User.LastLogon

    # Calculate the number of days since last logon
    $DaysSinceLastLogon = ($Today - $LastLogon).Days

    # Check if the user has been inactive for more than the specified number of days
    if ($DaysSinceLastLogon -ge $InactiveDays) {
        # Disable the user account
        Disable-LocalUser -Name $User.Name
        Write-Host "User $($User.Name) has been disabled due to inactivity for $($DaysSinceLastLogon) days."
    }
}