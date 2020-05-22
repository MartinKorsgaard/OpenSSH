$log = 'OpenSSH/Operational'

$oneFailedAttempt = [System.Collections.ArrayList]@()
$twoFailedAttempt = [System.Collections.ArrayList]@()
$blocked = [System.Collections.ArrayList]@()

$startTime = (Get-WinEvent -LogName $log -MaxEvents 1).TimeCreated

while ($true)
{   
    Start-Sleep -seconds 300

    write-host "Looking for failed events since $startTime"

    $failedEvents = Get-WinEvent -LogName $log -MaxEvents 1000 | Where -Property Message -match Failed | Where -property TimeCreated -gt $startTime

    $startTime = Get-Date

    write-host "Setting next run time to $startTime"

    foreach ($event in $failedEvents)
    {
        $event

        $ip = $event.Message.Split(" ")[8]
        write-host "Processing failed attempt by $ip..."
        
        if ($blocked -contains $ip) # already blocked
        {
            write-host "$ip is already blocked!"
        }
        else
        {
            if (-not $oneFailedAttempt -contains $ip)
            {
                write-host "$ip is not in list 1. Adding..."

                $oneFailedAttempt.Add($ip)
            }
            else
            {
                if (-not $twoFailedAttempt -contains $ip)
                {
                    write-host "$ip is not in list 2. Adding..."

                    $twoFailedAttempt.Add($ip)
                }
                else
                {
                    $name = "OpenSSH - Block $ip"

                    # if rule does not already exist, create it
                    if ((Get-NetFirewallRule -Name $ip -ErrorAction SilentlyContinue) -eq $null)
                    {
                        write-host "Adding Firewall rule..."
                                        
                        #block
                        $rule = New-NetFirewallRule -DisplayName $name -Name $ip -Direction Inbound -Action Block -RemoteAddress $ip

                        write-host "$ip is in list 1. Removing..."
                        write-host "$ip is in list 2. Removing..."

                        # cleanup failed attempt lists
                        $twoFailedAttempt.Remove($ip)
                        $oneFailedAttempt.Remove($ip)
                    }

                    $blocked.Add($ip)
                }
            }
        }
    }
}
