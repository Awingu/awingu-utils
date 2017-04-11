
<#

Sample Script to copy the awingu applications, drives, labels, icons, mediatypes, categories & apps from one instance to an other

#>

# Credentials for the Source:

$src = @{
    url = "https://source"
    login = "login1"
    pass = "pass1"
    domain = "domain"
    }

# Credentials for the Destination:

$dest = @{
    url = "https://destination"
    login = "login2"
    pass = "pass2"
    domain = "domain2"
    }

# Load Awingu API module

Import-Module $awinguapi

# Init stuff

$labelmap = @{}
$iconmap = @{}

# open source & destination session

$source = Start-AwinguSession -url $src.url -login $src.login -pass $src.pass
$destination = Start-AwinguSession -url $dest.url -login $dest.login -pass $dest.pass

# Set the correct active domains 

Set-AwinguActiveDomain -session $source -activedomain $src.domain
Set-AwinguActiveDomain -session $destination -activedomain $dest.domain

# Copy the labels & the icons + create a mapping file between the old icon & label numbers and the new ones

$labelmap = Copy-AwinguLabels -From $source -To $destination
$iconmap = Copy-AwinguIcons -From $source -To $destination

# Create the missing mediatypes & categories

Copy-AwinguMediaTypes -From $source -To $destination
Copy-AwinguCategories -From $source -To $destination

# Copy awingu servers, apps & drives

Copy-AwinguAppServers -from $source -to $destination -labelmap $labelmap
Copy-AwinguApps -From $source -To $destination -LabelMap $labelmap -IconMap $iconmap
Copy-AwinguDrives -from $source -to $destination -labelmap $labelmap

# Close sessions

Stop-AwinguSession -session $source
Stop-AwinguSession -session $destination