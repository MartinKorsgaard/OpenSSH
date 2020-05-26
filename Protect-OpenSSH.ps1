$log = 'OpenSSH/Operational'

$oneFailedAttempt = [System.Collections.ArrayList]@()
$twoFailedAttempt = [System.Collections.ArrayList]@()
$blocked = [System.Collections.ArrayList]@()

$regex = [regex] "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"

# set start time to the newest log post and subtract 1 day
$newStartTime = ((Get-WinEvent -LogName $log -MaxEvents 1).TimeCreated).AddDays(-1)

while ($true)
{   
    # set actual start time   
    $startTime = $newStartTime

    # sleep 5 minutes
    Start-Sleep -seconds 300

    # set new start time to be used in next cycle
    $newStartTime = Get-Date

    # get events based on start time
    $events = Get-WinEvent -LogName $log -MaxEvents 1000 | Where -property TimeCreated -gt $startTime

    # sort out the failed events
    $failed = $events | Where -Property Message -like "*Failed password for * from *" 

    write-host "Looking for failed passwords since $startTime"

    # start processing failed events
    foreach ($event in $failed)
    {
        $event | format-list

        # isolate ip from string
        $ip = $regex.Matches($event.Message.Split(" ")) | %{ $_.value } | select -first 1

        write-host "Processing failed password from $ip..."
        
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
                        $rule = New-NetFirewallRule -DisplayName $name -Name $ip -Direction Inbound -Action Block -RemoteAddress $ip -Group "OpenSSH Protect"

                        # cleanup failed attempt lists
                        write-host "$ip is in list 1. Removing..."
                        $oneFailedAttempt.Remove($ip)

                        write-host "$ip is in list 2. Removing..."
                        $twoFailedAttempt.Remove($ip)
                    }

                    $blocked.Add($ip)
                }
            }
        }
    }

    # sort out accepted events
    $accepted = $events | Where -Property Message -like "*Accepted password for * from *"

    write-host "Looking for accepted passwords since $startTime"

    # start processing accepted events
    foreach ($event in $accepted)
    {
        $event | format-list

        # isolate ip address from string
        $ip = $regex.Matches($event.Message.Split(" ")) | %{ $_.value } | select -first 1

        write-host "Processing accepted password from $ip..."

        if ($oneFailedAttempt -contains $ip)
        {
            write-host "$ip is in list 1. Removing..."

            $oneFailedAttempt.Remove($ip)
        }

        if ($twoFailedAttempt -contains $ip)
        {
            write-host "$ip is in list 2. Removing..."

            $twoFailedAttempt.Remove($ip)
        }
    }
}
