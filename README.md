# OpenSSH
OpenSSH on Windows

Added Protect-OpenSSH.ps1 to help protect OpenSSH from brute force attacks. It will check the log for failed attempts every 5 minutes and block all IP's with 3 or more failed attempts by creating a firewall rule. This script is only ment to be run on Windows.
