$username = "username"
$maxInactiveDays = 30
$maxInactiveDate = (Get-Date).AddDays(-$maxInactiveDays)

$lastLogon = Get-WinEvent -FilterHashtable @{
    LogName='Security';
    ID=4624;
    StartTime=$maxInactiveDate
} | Where-Object {$_.Properties[5].Value -eq $username} | Select-Object -First 1

if ($lastLogon -eq $null) {
    Disable-LocalUser -Name $username
}