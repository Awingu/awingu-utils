<# 
 .Synopsis
  Awingu API Module

 .Description
  Easy way to interact via Powershell with the Awingu API
#>


function Start-AwinguSession {
    param(

        [Parameter(Mandatory=$True)]
        [string]$url,

        [Parameter(Mandatory=$True)]
        [string]$login,
	
        [Parameter(Mandatory=$false)]
        [string]$domain,

        [Parameter(Mandatory=$True)]
        [string]$pass
    )
    
    $headers = @{}
    $headers.Add("Content-Type", "application/json")

    $sessionurl = $url + "/api/sessions/"

    if ($domain -eq "") { 

        $logindata = @{
            username=$login
            password=$pass
            }

        } else {

        $logindata = @{
            username=$login
            password=$pass
            domain=$domain
            }
        }

    $json = $logindata | ConvertTo-Json
 
    try { 
            $webrequest = Invoke-RestMethod -Method Post -Uri $sessionurl -SessionVariable mysession -Body $json -Headers $headers
        } catch {

            Write-Host "Error while logging in to $sessionsurl"
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

            break
        }
    
    $cookies = $mysession.Cookies.GetCookies($sessionurl) 

    $csrftoken = $cookies.Get_Item("csrftoken").value
    $sessionid = $cookies.Get_Item("sessionid").value

    Add-Member -InputObject $mysession -MemberType NoteProperty -Name url -Value $url
    Add-Member -InputObject $mysession -MemberType NoteProperty -Name csrftoken -Value $csrftoken
    Add-Member -InputObject $mysession -MemberType NoteProperty -Name sessionid -Value $sessionid

    $mysession.Headers.Add("Accept","")
    $mysession.Headers.Add("Referer",$url)
    $mysession.Headers.Add("X-CSRFToken",$csrftoken)

    return $mysession
    }

function Stop-AwinguSession {
    param(

        [Parameter(Mandatory=$True)]
        $session
    )

    $url = $session.url + "/api/sessions/"


    try { 
            Invoke-RestMethod -Method delete -Uri $url -WebSession $session 
            

        } catch {

            Write-Host "Error while loggin out from $url"
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

            break
        }

}

function Get-AwinguLabels {
    param(
        [Parameter(Mandatory=$false)]
        $activedomain, 

        [Parameter(Mandatory=$True)]
        $session
    )

    $url = $session.url + "/api/labels/"
    
    try { 
            $labels = Invoke-RestMethod -Method get -Uri $url -WebSession $session 
            
            return $labels.objects

        } catch {

            Write-Host "Error while getting labels from $url"
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

            break
        }

}

function Get-AwinguDomains {
    param(

        [Parameter(Mandatory=$True)]
        $session
    )

    $url = $session.url + "/smc-api/domains/"


    try { 
            $domains = Invoke-RestMethod -Method get -Uri $url -WebSession $session 
            
            return $domains.objects

        } catch {

            Write-Host "Error while getting domains from $url"
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

            break
        }

}


function Add-AwinguUserGroup {
    param(

        [Parameter(Mandatory=$True)]
        $session,
        [Parameter(Mandatory=$True)]
        [string]$group,
        [Parameter(Mandatory=$false)]
        [boolean]$whitelist
    )

    $url = $session.url + "/smc-api/domains/" + $session.activedomain + "/userconnector/usergroups/"

    if ($whitelist -eq "") {
           $whitelist = [boolean]$false
           }


   $payload = @{

           isSignInWhiteListed = $whitelist
           name = $group
 
           }

    $json = $payload | ConvertTo-Json


    # Add Group 

    try { 
            $devnull = Invoke-RestMethod -Method Post -Uri $url -WebSession $session -Body $json
            
        } catch {

            Write-Host "Error while adding group $group from $url"
            Write-Host $json

            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

            break
        }


}

function Set-AwinguWhiteList {
    param(

        [Parameter(Mandatory=$True)]
        $session,
        [Parameter(Mandatory=$True)]
        [boolean]$status
    )

    # Find All label

    $all = Find-AwinguLabel -session $session -key "all"
    $label = "/api/labels/" + $all + "/"

    if ( $status -eq $True ) {

            # Add it to the features connector

            $url = $session.url + "/smc-api/features/userconnector.sign_in_white_list/labels/"
            
            $payload = @{
                    labelUri = $label
                    }

            $json = $payload | ConvertTo-Json

            try { 
                    $devnull = Invoke-RestMethod -Method Post -Uri $url -WebSession $session -Body $json
            
                } catch {

                    Write-Host "Error while enabling whiltelist from $url"
                    Write-Host $json

                    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
                    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

                    break
                }



            }  else {


            # Delete it from the features connector

            $url = $session.url + "/smc-api/features/userconnector.sign_in_white_list/labels/" + $all + "/"
            

            try { 
                    $devnull = Invoke-RestMethod -Method Delete -Uri $url -WebSession $session
            
                } catch {

                    Write-Host "Error while disabling whitelist from $url"
                    Write-Host $json

                    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
                    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

                    break
                }


            }

}



function Add-AwinguDomain{
    param(

        [Parameter(Mandatory=$True)]
        $session,
        [Parameter(Mandatory=$True)]
        [string]$netbios,
        [Parameter(Mandatory=$True)]
        [string]$name,
        [Parameter(Mandatory=$True)]
        [string]$fqdn,
        [Parameter(Mandatory=$True)]
        [string]$ldap,
        [Parameter(Mandatory=$True)]
        [string]$basedn,
        [Parameter(Mandatory=$false)]
        [boolean]$ssl,
        [Parameter(Mandatory=$false)]
        [string]$hostheader,
        [Parameter(Mandatory=$false)]
        [string]$bindname,
        [Parameter(Mandatory=$false)]
        [string]$bindpass,
        [Parameter(Mandatory=$false)]
        [string]$dns,
        [Parameter(Mandatory=$false)]
        [boolean]$isAdmin
    )

    $url = $session.url + "/smc-api/domains/"

    if ($isAdmin -eq "") {
           $isAdmin = [boolean]$false
           }
    
    if ($ssl -eq "") {
           $ssl = [boolean]$false
           }

    # if not create it and return id, if it exist return the id of the matching existing mediatype


    $payload = @{

           netbios = $netbios
           name = $name
           fqdn = $fqdn
           hostHeader = $hostheader
           isAdmin = $isAdmin
           bindName = $bindname
           bindPassword = $bindpass
 
           }

    $json = $payload | ConvertTo-Json



    # Create domain 

    try { 
            $devnull = Invoke-RestMethod -Method Post -Uri $url -WebSession $session -Body $json
            
        } catch {

            Write-Host "Error while creating domain $name / $netbios from $url"
            Write-Host $json

            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

            break
        }

 
    Set-AwinguActiveDomain -session $session -activedomain $name

        
    # Create user connector 
    $url = $session.url + "/smc-api/domains/" + $name + "/userconnector" 

 
    try { 


        $payload = @{}
        $json = $payload | ConvertTo-Json
         
        $userconnector =  Invoke-RestMethod -Method Put -Uri $url -WebSession $session -Body $json 

        if ( $ssl -eq $true) {

                # Enable SSL Feature
                $url =  $session.url + "/smc-api/features/userconnector.ldap.ssl/labels/"

                $ssllabel = Find-AwinguLabel -session $session -key "all"
                $ssllabel = "/api/labels/" + $ssllabel + "/"

                $payload = @{

                        labelUri = $ssllabel

                        }
                
                $json = $payload | ConvertTo-Json

                Invoke-RestMethod -Method Post -Uri $url -WebSession $session -Body $json 

                }
                
        $userconnector = $userconnector| ConvertFrom-Json2
            
        $userconnector.functions.createBindName = "builtin.create_domain_bind_name"
        $userconnector.functions.findGroups = "builtin.find_groups_by_member_of"
        $userconnector.ldap.server = $ldap
        $userconnector.ldap.baseDn = $basedn

        $json = $userconnector | ConvertTo-Json

        $url = $session.url + "/smc-api/domains/" + $name + "/userconnector" 

        $userconnector =  Invoke-RestMethod -Method Put -Uri $url -WebSession $session -Body $json | ConvertFrom-Json2

        } catch {

            Write-Host "Error while creating user connector $name from $url"
            Write-Host $json

            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

            break
        }
    


        return $userconnector 
    
       

}

function Add-AwinguDomain35 {
    param(

        [Parameter(Mandatory=$True)]
        $session,
        [Parameter(Mandatory=$True)]
        [string]$netbios,
        [Parameter(Mandatory=$True)]
        [string]$name,
        [Parameter(Mandatory=$True)]
        [string]$fqdn,
        [Parameter(Mandatory=$True)]
        [string]$ldap,
        [Parameter(Mandatory=$True)]
        [string]$basedn,
        [Parameter(Mandatory=$false)]
        [boolean]$ssl,
        [Parameter(Mandatory=$false)]
        [string]$hostheader,
        [Parameter(Mandatory=$false)]
        [string]$bindname,
        [Parameter(Mandatory=$false)]
        [string]$bindpass,
        [Parameter(Mandatory=$false)]
        [string]$dns,
        [Parameter(Mandatory=$false)]
        [boolean]$isAdmin
    )

    $url = $session.url + "/smc-api/domains/"

    if ($isAdmin -eq "") {
           $isAdmin = [boolean]$true
           }
    
    if ($ssl -eq "") {
           $ssl = [boolean]$false
           }

    # if not create it and return id, if it exist return the id of the matching existing mediatype


    $payload = @{

           netbios = $netbios
           name = $name
           fqdn = $fqdn
           hostHeader = $hostheader
           isAdmin = $isAdmin
           bindName = $bindname
           bindPassword = $bindpass
           baseDn = $basedn
           server = $ldap
           createBindName = "builtin.create_domain_bind_name"
           findGroups = "builtin.find_groups_by_member_of"
           ssl = $ssl
           }

    $json = $payload | ConvertTo-Json



    # Create domain 

    try { 
            $devnull = Invoke-RestMethod -Method Post -Uri $url -WebSession $session -Body $json

            
        } catch {

            Write-Host "Error while creating domain $name / $netbios from $url"
            Write-Host $json

            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

            break
        }

 
    Set-AwinguActiveDomain -session $session -activedomain $name

    Start-Sleep 5 
        
    # Create user connector 
    $url = $session.url + "/smc-api/domains/" + $name + "/userconnector/" 

 
    try { 
    
        $payload = @{
        
            radius = @{
                        isEnabled = $false
                        port = ""
                        secret = ""
                        servers = ""
                     }
                   
                   
                   }

        $json = $payload | ConvertTo-Json
         
        $userconnector =  Invoke-RestMethod -Method Put -Uri $url -WebSession $session -Body $json 
              
        } catch {

            Write-Host "Error while creating user connector $name from $url"
            Write-Host $json

            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

            break
        }
    

        if ( $ssl -eq $true) {

            # Enable SSL Feature
            $url =  $session.url + "/smc-api/features/userconnector.ldap.ssl/labels/"

            $ssllabel = Find-AwinguLabel -session $session -key "all"
            $ssllabel = "/api/labels/" + $ssllabel + "/"

            $payload = @{

                    labelUri = $ssllabel

                    }
                
            $json = $payload | ConvertTo-Json

            try {
        
                Invoke-RestMethod -Method Post -Uri $url -WebSession $session -Body $json 

                } catch {
                
                    Write-Host "Error while setting SSL ON from $url"
                    Write-Host $json

                    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
                    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

                    break
                }



            }




        return $userconnector 
    
       

}





function Get-AwinguAppIcons {
    param(

        [Parameter(Mandatory=$True)]
        $session
    )

    $url = $session.url + "/api/appicon/"

    try { 
            $icons = Invoke-RestMethod -Method get -Uri $url -WebSession $session 
            
            return $icons.objects

        } catch {

            Write-Host "Error while getting icons from $url - v2"
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

            break
        }

}

function Get-AwinguAppIcon {
    param(

        [Parameter(Mandatory=$True)]
        $session,

        [Parameter(Mandatory=$True)]
        [int]$iconid,

        [Parameter(Mandatory=$False)]
        [string]$filename
        
    )

    $url = $session.url + "/api/appicon/" + $iconid

    if ($filename -eq "") {
    
        $filename = [System.IO.Path]::GetTempFileName()
      
        }

    try { 
            Invoke-RestMethod -Method get -Uri $url -WebSession $session -OutFile $filename

            return $filename
            
        } catch {

            Write-Host "Error while getting icon from $url "
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

            break
        }

}

function Get-AwinguCategories {
   param(
        [Parameter(Mandatory=$false)]
        $activedomain, 

        [Parameter(Mandatory=$True)]
        $session,

        [parameter(Mandatory=$false)]
        [switch]$nobuildincategories
    )

    $url = $session.url + "/api/categories/"
    
    try { 
            $categories = Invoke-RestMethod -Method get -Uri $url -WebSession $session 

            if ($nobuildincategories) {

                    return $categories.objects |  Where-Object {$_.domain -ne "" }
                }
            
            return $categories.objects

        } catch {

            Write-Host "Error while getting categories from $url"
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

            break
        }

}

function Get-AwinguMediaTypes {
   param(
        [Parameter(Mandatory=$false)]
        $activedomain, 

        [Parameter(Mandatory=$True)]
        $session,

        [parameter(Mandatory=$false)]
        [switch]$nobuildinmediatypes
    )

    $url = $session.url + "/api/mediatypes/"
    
    try { 
            $mediatypes = Invoke-RestMethod -Method get -Uri $url -WebSession $session 

            if ($nobuildinmediatypes) {

                    return $mediatypes.objects |  Where-Object {$_.domain -ne "" }
                }
            
            return $mediatypes.objects

        } catch {

            Write-Host "Error while getting mediatypes from $url"
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

            break
        }

}

function Get-AwinguDrives {
   param(
        [Parameter(Mandatory=$false)]
        $activedomain, 

        [Parameter(Mandatory=$True)]
        $session
    )

    $url = $session.url + "/api/drives/"
    
    try { 
            $drives = Invoke-RestMethod -Method get -Uri $url -WebSession $session 
            
            return $drives.objects

        } catch {

            Write-Host "Error while getting drives from $url"
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

            break
        }

}

function Get-AwinguAppServers {
   param(
        [Parameter(Mandatory=$false)]
        $activedomain, 

        [Parameter(Mandatory=$True)]
        $session
    )

    $url = $session.url + "/api/appservers/"
    
    try { 
            $appservers = Invoke-RestMethod -Method get -Uri $url -WebSession $session 
            
            return $appservers.objects

        } catch {

            Write-Host "Error while getting categories from $url"
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

            break
        }

}

function Set-AwinguActiveDomain {
    param(

        [Parameter(Mandatory=$True)]
        $session,

        [Parameter(Mandatory=$True)]
        [string]$activedomain

    )

    $payload = @{
        managingDomain=$activedomain
        }

    $json = $payload | ConvertTo-Json

    $url = $session.url + "/api/sessions/"

    try { 
          $webrequest = Invoke-RestMethod -Method Put -Uri $url -WebSession $session -Body $json 

          Add-Member -InputObject $session -MemberType NoteProperty -Name activedomain -Value $activedomain -Force


        } catch {

            Write-Host "Error while setting active domains to $activedomain via $url"
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

            break
        }

}

function Find-AwinguLabel {
    param(
        [Parameter(Mandatory=$True)]
        $session,

        [Parameter(Mandatory=$True)]
        [string]$key,

        [Parameter(Mandatory=$false)]
        [string]$value
    )

    $id = 0;

    Get-AwinguLabels -session $session | ForEach-Object {

        $label_key = $_.key
        $label_value = $_.value
        $label_id = Get-AwinguID $_.uri

        if (($label_key -eq $key) -and ($label_value -eq $value))  { 
                $id = $label_id
            }

        }

    return $id

    }

function Find-AwinguDrive {
    param(
        [Parameter(Mandatory=$True)]
        $session,

        [Parameter(Mandatory=$True)]
        [string]$name
    )

    $id = 0;

    Get-AwinguDrives -session $session | ForEach-Object {
              
        $drivesname = $_.name
        $drivesid = Get-AwinguID $_.uri

        if ($drivesname -eq $name )  { 
                $id = $drivesid
            }

        }

    return $id

    }

function Add-AwinguLabel {
    param(
        [Parameter(Mandatory=$True)]
        $session,

        [Parameter(Mandatory=$True)]
        [string]$key,

        [Parameter(Mandatory=$false)]
        [string]$value
    )

    $url = $session.url + "/api/labels/"

    # Check if label already exists

    $labelid = Find-AwinguLabel -key $key -value $value -session $session

    # if not create it and return label id, if it exist return the label id of the matching existing label

    if ($labelid -eq 0) {

        $payload = @{
            key = $key
            value = $value
            }

        $json = $payload | ConvertTo-Json

        $webrequest = Invoke-RestMethod -Method Post -Uri $url -WebSession $session -Body $json 

        return Get-AwinguID $webrequest.uri 


        } else {

            return $labelid

        }

    }

function Add-AwinguCategory {
    param(
        [Parameter(Mandatory=$True)]
        $session,

        [Parameter(Mandatory=$True)]
        [string]$category
    )

    $url = $session.url + "/api/categories/"

    # Check if category already exists

    $categoryid = Find-AwinguCategory -category $category -session $session

    # if not create it and return id

    if ($categoryid -eq 0) {

        $payload = @{
            name = $category
            }

        $json = $payload | ConvertTo-Json

        $webrequest = Invoke-RestMethod -Method Post -Uri $url -WebSession $session -Body $json     

        return Get-AwinguID $webrequest.uri 


        } else {

            return $categoryid

        }

    }

function Add-AwinguMediaType {
    param(
        [Parameter(Mandatory=$True)]
        $session,

        [Parameter(Mandatory=$True)]
        [string]$mediatype,

        [Parameter(Mandatory=$false)]
        [string]$medianame,

        [Parameter(Mandatory=$false)]
        [string]$mediadescription

    )

    $url = $session.url + "/api/mediatypes/"

    if ($mediadescription -eq "") {
           $mediadescription = $mediatype
           }

    if ($medianame -eq "") {
           $medianame = $mediatype
           }

    # Check if mediatype already exists

    $mediatypeid = Find-AwinguMediaType -mediatype $mediatype -session $session

    # if not create it and return id, if it exist return the id of the matching existing mediatype

    if ($mediatypeid -eq 0) {

        $payload = @{
            contentType = $mediatype
            description = $mediadescription
            name = $medianame
            }

        $json = $payload | ConvertTo-Json

        $webrequest = Invoke-RestMethod -Method Post -Uri $url -WebSession $session -Body $json   

        return Get-AwinguID $webrequest.uri

        } else {

            return $mediatypeid

        }

    }

function Add-AwinguDrive {
    param(
        [Parameter(Mandatory=$True)]
        $session,

        [Parameter(Mandatory=$True)]
        [string]$name,

        [Parameter(Mandatory=$True)]
        [string]$backend,

        [Parameter(Mandatory=$True)]
        [string]$url,

        [Parameter(Mandatory=$False)]
        [string]$unc,

        [Parameter(Mandatory=$False)]
        [string]$description,

        [Parameter(Mandatory=$False)]
        [boolean]$usedomain,

        [Parameter(Mandatory=$False)]
        [array]$config

    )

    # $url already exists as parameter so exceptionally we call this api call $wurl

    $wurl = $session.url + "/api/drives/"

    # Fill up optional values if needed 

    if ($description -eq "") {
           $description = "/"
           }

    if ($usedomain -eq "") {
           $usedomain = [boolean]$False
           }

    if ($config -eq $null ) {
           $config = New-Object System.Collections.ArrayList($null)
           }

    # Check if drive already exists

    $driveid = Find-AwinguDrive -name $name -session $session

    # if not create it and return id, if it exist return the id of the matching existing mediatype

    if ($driveid -eq 0) {

        $payload = @{

           name = $name
           description = $description
           backend = $backend
           url = $url
           unc = $unc
           config = $config
           useDomain = $usedomain
           }

        $json = $payload | ConvertTo-Json

        try {

            $webrequest = Invoke-RestMethod -Method Post -Uri $wurl -WebSession $session -Body $json   

            return Get-AwinguID $webrequest.uri

            } catch {

            Write-Host "Error while adding drive $wurl"
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
            
            $session

            $json

            $driveid

            break

            }


        } else {

            return $driveid

        }

    }

function Add-AwinguApp {
    param(
        [Parameter(Mandatory=$True)]
        $session,

        [Parameter(Mandatory=$True)]
        [string]$name,

        [Parameter(Mandatory=$False)]
        [string]$description,


        [Parameter(Mandatory=$True)]
        [string]$protocol,

        [Parameter(Mandatory=$False)]
        [string]$icon,

        [Parameter(Mandatory=$True)]
        [string]$command,

        [Parameter(Mandatory=$False)]
        [boolean]$supportsUnicodeKbd,

        [Parameter(Mandatory=$False)]
        [boolean]$startInForeground

    )

    $url = $session.url + "/api/apps/"

    # Fill up optional values if needed 

    if ($description -eq "") {
           $description = "/"
           }

    if ($icon -eq "") {
           $icon = "/"
           }

    if ($command -eq "empty") {
           $command = ""
           }

    if ($startInForeground -eq $null) {
           $startInForeground = [boolean]$False
           }

    if ($supportsUnicodeKbd -eq $null) {
           $supportsUnicodeKbd = [boolean]$True
           }

    # Create Payload

    $payload = @{

         name= $name
         description= $description
         icon=  $icon
         protocol=  $protocol
         command= $command
         supportsUnicodeKbd= $supportsUnicodeKbd
         startInForeground= $startInForeground
         }

    $json = $payload | ConvertTo-Json

    $webrequest = Invoke-RestMethod -Method Post -Uri $url -WebSession $session -Body $json   

    return Get-AwinguID $webrequest.uri

    }

function Add-AwinguLabelToApp {
    param(
        [Parameter(Mandatory=$True)]
        $session,

        [Parameter(Mandatory=$True)]
        [int]$appid,

        [Parameter(Mandatory=$True)]
        [string]$labeltype,

        [Parameter(Mandatory=$True)]
        [int]$labelid

    )

    $applabelsurl = $session.url + "/api/apps/" + $appid + "/" + $labeltype + "/"
    $labeluri = "/api/labels/" + $labelid + "/"

    $payload = @{

        labelUri = $labeluri

        }

    $json = $payload | ConvertTo-Json 

    $webrequest = Invoke-RestMethod -Method post -Uri $applabelsurl -WebSession $session -Body $json
    
    }

function Add-AwinguLabelToDrive {
    param(
        [Parameter(Mandatory=$True)]
        $session,

        [Parameter(Mandatory=$True)]
        [int]$driveid,

        [Parameter(Mandatory=$True)]
        [string]$labeltype,

        [Parameter(Mandatory=$True)]
        [int]$labelid

    )

    $driveslabelsurl = $session.url + "/api/drives/" + $driveid + "/" + $labeltype + "/"
    $labeluri = "/api/labels/" + $labelid + "/"

    $payload = @{

        labelUri = $labeluri

        }

    $json = $payload | ConvertTo-Json 

    $webrequest = Invoke-RestMethod -Method post -Uri $driveslabelsurl -WebSession $session -Body $json
                                                
    }


function Add-AwinguLabelToAppServer {
    param(
        [Parameter(Mandatory=$True)]
        $session,

        [Parameter(Mandatory=$True)]
        [int]$appserverid,

        [Parameter(Mandatory=$True)]
        [string]$labeltype,

        [Parameter(Mandatory=$True)]
        [int]$labelid

    )

    $driveslabelsurl = $session.url + "/api/appservers/" + $appserverid + "/" + $labeltype + "/"
    $labeluri = "/api/labels/" + $labelid + "/"

    $payload = @{

        labelUri = $labeluri

        }

    $json = $payload | ConvertTo-Json 

    try {

            $webrequest = Invoke-RestMethod -Method post -Uri $driveslabelsurl -WebSession $session -Body $json
        
        } catch
        {

        }                                        
    }



function Add-AwinguCategoryToApp {
    param(
        [Parameter(Mandatory=$True)]
        $session,

        [Parameter(Mandatory=$True)]
        [int]$appid,

        [Parameter(Mandatory=$True)]
        [int]$categoryid

    )

    $appcategoryurl = $session.url + "/api/apps/" + $appid + "/categories/"
    $categoryuri = "/api/categories/" + $categoryid + "/"

    $payload = @{

        categoryUri = $categoryuri

        }

    $json = $payload | ConvertTo-Json 

    $webrequest = Invoke-RestMethod -Method post -Uri $appcategoryurl -WebSession $session -Body $json
    
    
      
    }

function Add-AwinguMediaTypeToApp {
    param(
        [Parameter(Mandatory=$True)]
        $session,

        [Parameter(Mandatory=$True)]
        [int]$appid,

        [Parameter(Mandatory=$True)]
        [int]$mediatypeid

    )

    $appmediatypesurl = $session.url + "/api/apps/" + $appid + "/mediatypes/"
    $mediatypesuri = "/api/labels/" + $mediatypeid + "/"

    $payload = @{

        mediaTypeUri = $mediatypesuri

        }

    $json = $payload | ConvertTo-Json 

    $webrequest = Invoke-RestMethod -Method post -Uri $appmediatypesurl -WebSession $session -Body $json

    
    }

function Get-AwinguID {

    return split-path $args[0] -leaf

    }

function Get-AwinguApps {
    param(
        [Parameter(Mandatory=$false)]
        $activedomain, 

        [Parameter(Mandatory=$True)]
        $session,

        [parameter(Mandatory=$false)]
        [switch]$nobuildinapps

    )

    $url = $session.url + "/api/apps/"

    $excludeappkeys = 'Browser Check', 'CDDASHBOARD', 'INSIGHTS', 'Preview', 'RDPV', 'SMC'
    
    $counter = 0

    try { 
            $apps = Invoke-RestMethod -Method get -Uri $url -WebSession $session 

            $apps = $apps.objects

            $apps | ForEach-Object {

                $this_app = $_

                if (-not ($excludeappkeys | ? { $this_app.key -contains $_ }) ) { 

                    Add-Member -InputObject $apps[$counter] -MemberType NoteProperty -Name buildinapp -Value $false -Force

                    } else {

                    Add-Member -InputObject $apps[$counter] -MemberType NoteProperty -Name buildinapp -Value $true -Force

                    }

                $counter = $counter + 1 

                }

            if ($nobuildinapps) {

                    return $apps |  Where-Object {$_.buildinapp -eq $false }
                }  
                
                return $apps

        } catch {

            Write-Host "Error while getting apps from $url"
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

            break
        }

}


function Set-AwinguBackground {
    param(
        [Parameter(Mandatory=$false)]
        $activedomain, 
        [Parameter(Mandatory=$True)]
        $session,
        [Parameter(Mandatory=$False)]
        $file,
        [Parameter(Mandatory=$True)]
        [boolean]$useCustomBackground
    )

    Add-Type -AssemblyName "System.Web"

    

    try {
            $url = $session.url + "/smc-api/branding/"

            $branding = Invoke-RestMethod -Uri $url -Method Get -WebSession $session
            
            $branding.useCustomBackground = $useCustomBackground

            $json = $branding | ConvertTo-Json

            $branding = Invoke-RestMethod -Uri $url -Method put -Body $json -WebSession $session


        } catch {

            Write-Host "Error while setting custombackground from $url"
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

            break

        }

 
    if ($PSBoundParameters.ContainsKey('file')) {
    
         


    $boundary = [guid]::NewGuid().ToString()
    $url = $session.url + "/smc-api/branding/custom/desktop/background/"	
    
    $filename = Split-Path $file -leaf
    $filebin = [System.IO.File]::ReadAllBytes($file)
    $filetype = [System.Web.MimeMapping]::GetMimeMapping($file)

    $enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")

$template = @'
--{0}
Content-Disposition: form-data; name="fileData"; filename="{1}"
Content-Type: {2}

{3}
--{0}--

'@

    $body = $template -f $boundary, $filename, $filetype, $enc.GetString($filebin)

    try {

            $webrequest = Invoke-RestMethod -Uri $url -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $body -WebSession $session

        } catch {

            Write-Host "Error while uploading background image from $url with file $file"
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

            break

        }

    }

}




function Add-AwinguAppIcon {
    param(
        [Parameter(Mandatory=$false)]
        $activedomain, 

        [Parameter(Mandatory=$True)]
        $session,

        [parameter(Mandatory=$True)]
        [string]$file,

        [parameter(Mandatory=$false)]
        [string]$filename,
        
        [parameter(Mandatory=$True)]
        [string]$filetype

    )

	$boundary = [guid]::NewGuid().ToString()
    $url = $session.url + "/api/appicon/"	
    
    if ($filename -eq "") {
	    $filename = Split-Path $InFile -leaf
        }

   	$filebin = [System.IO.File]::ReadAllBytes($file)
    $enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")

    $template = @'
--{0}
Content-Disposition: form-data; name="fileData"; filename="{1}"
Content-Type: {2}

{3}
--{0}--

'@

    $body = $template -f $boundary, $filename, $filetype, $enc.GetString($filebin)

	try	{
		$webrequest = Invoke-RestMethod -Uri $url -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $body -WebSession $session
        
        return Get-AwinguID $webrequest.uri

		}
		catch [Exception]
		{
			$PSCmdlet.ThrowTerminatingError($_)
		}       

    }

function Find-AwinguCategory {
    param(
        [Parameter(Mandatory=$True)]
        $session,

        [Parameter(Mandatory=$True)]
        [string]$category
    )
 
    $id = 0;

    Get-AwinguCategories -session $session | ForEach-Object {
              
        $categoryname = $_.name
        $categoryid = Get-AwinguID $_.uri

        if ($categoryname -eq $category )  { 
                $id = $categoryid
            }

        }

    return $id

    }

function Find-AwinguMediaType {
    param(
        [Parameter(Mandatory=$True)]
        $session,

        [Parameter(Mandatory=$True)]
        [string]$mediatype
    )
 
    $id = 0;

    Get-AwinguMediaTypes -session $session | ForEach-Object {
                         
        $mediatypename = $_.contentType
        $mediatypeid = Get-AwinguID $_.uri
  
        if ($mediatypename -eq $mediatype)  { 
                $id = $mediatypeid
            }

        }

    return $id

    }



function Copy-AwinguLabels {
    param(
        [Parameter(Mandatory=$True)]
        $From,

        [Parameter(Mandatory=$True)]
        $To
    )
 
    $labelmap = @{}

    Get-AwinguLabels -session $From | ForEach-Object {

        $label_key = $_.key
        $label_value = $_.value
        $label_id = Get-AwinguID $_.uri

        if ($label_value -eq "") {

            $id = Add-AwinguLabel -session $To -key $label_key

            } else {

            $id = Add-AwinguLabel -session $To -value $label_value -key $label_key
      
            }
    
        # Map label ID's from source and destination session

        $labelmap.Add($label_id,$id)     
        }


    return $labelmap

    }


function Copy-AwinguIcons {
    param(
        [Parameter(Mandatory=$True)]
        $From,

        [Parameter(Mandatory=$True)]
        $To
    )
 
    $list =  New-Object System.Collections.ArrayList

    Get-AwinguApps -session $From -nobuildinapps| ForEach-Object {
        [void] $list.add($_.icon)
        }

    $iconmap = @{}
 
    Get-AwinguAppIcons -session $From | ForEach-Object {

        $icon = $_

        if ($icon.uri -in $list) {

            $icon_id_source = Get-AwinguID $icon.uri

            $tmpfile = Get-AwinguAppIcon -session $From -iconid $icon_id_source
    
            $icon_id_dest = Add-AwinguAppIcon -session $To -file $tmpfile -filetype $icon.contentType -filename $icon.filename

            Remove-Item -Path $tmpfile

            # Map Icon ID's from source and destination session

            $iconmap.Add($icon_id_source,$icon_id_dest)
 
            }        
        }

    return $iconmap

    }



function Copy-AwinguCategories {
    param(
        [Parameter(Mandatory=$True)]
        $From,

        [Parameter(Mandatory=$True)]
        $To
    )

    Get-AwinguCategories -nobuildincategories -session $From | ForEach-Object {

        $null = Add-AwinguCategory -session $To -category $_.name

        }

    }


function Copy-AwinguMediaTypes {
    param(
        [Parameter(Mandatory=$True)]
        $From,
        [Parameter(Mandatory=$True)]
        $To
    )

    Get-AwinguMediaTypes -nobuildinmediatypes -session $From | ForEach-Object { 

        $null = Add-AwinguMediaType -session $To -mediatype $_.contenttype -mediadescription $_.description -medianame $_.name

        }
    }


function Add-AwinguAppServer {
    param(
        [Parameter(Mandatory=$True)]
        $Session,
        [Parameter(Mandatory=$True)]
        [string]$Name,
        [Parameter(Mandatory=$True)]
        [string]$Host,
        [Parameter(Mandatory=$false)]
        [int]$Port,
        [Parameter(Mandatory=$false)]
        [int]$MaxConnections
    )

    $url = $session.url + "/api/appservers/"

    if ($port -eq "") {

        $port = 3389;
        }

    if ($MaxConnections -eq "") {
        $MaxConnections = 100
        }

    $payload = @{

         description = ""
         enabled = $true
         host = $Host 
         maxConnections = $MaxConnections
         name = $Name 
         port = $Port 

         }

    $json = $payload | ConvertTo-Json

    try {
            $webrequest = Invoke-RestMethod -Method Post -Uri $url -WebSession $session -Body $json   
        
        } catch {

            $json
            $url

            Write-Host "Error while getting apps from $url"
            Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
            Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription

        }


    return Get-AwinguID $webrequest.uri

}


function Copy-AwinguDrives {
    param(
        [Parameter(Mandatory=$True)]
        $From,
        [Parameter(Mandatory=$True)]
        $To,
        [Parameter(Mandatory=$True)]
        $LabelMap
    )


    Get-AwinguDrives -session $From | ForEach-Object {

        $this_drive = $_

        $drive_id = Add-AwinguDrive -session $To -backend $this_drive.backend `
                                                       -url $this_drive.url `
                                                       -name $this_drive.name `                                                       -unc $this_drive.unc `                                                       -usedomain $this_drive.usedomain `
                                                       -config $this_drive.config

        # Attach Labels
                       
        $this_drive.labels | ForEach-Object {

            $label_id_source = Get-AwinguID $_.uri
            $label_id_dest = $labelmap.Get_Item($label_id_source)
                
            Add-AwinguLabelToDrive -session $To -driveid $drive_id -labeltype "labels" -labelid $label_id_dest

            }           
    
        # Attach Userlabels
                       
        $this_drive.userlabels | ForEach-Object {

            $label_id_source = Get-AwinguID $_.uri
            $label_id_dest = $labelmap.Get_Item($label_id_source)
                
            Add-AwinguLabelToDrive -session $To -driveid $drive_id -labeltype "userlabels" -labelid $label_id_dest

            }  

        }
    }


function Copy-AwinguAppServers {
    param(
        [Parameter(Mandatory=$True)]
        $From,
        [Parameter(Mandatory=$True)]
        $To,
        [Parameter(Mandatory=$True)]
        $LabelMap
    )


    Get-AwinguAppServers -session $From | ForEach-Object {

        $this_server = $_

        $server_id = Add-AwinguAppServer -session $To -Name $this_server.name  `
                                         -Host $this_server.host 


        # Attach Serverlabels
                     
        $this_server.labels | ForEach-Object {

            $label_id_source = Get-AwinguID $_.uri
            $label_id_dest = $labelmap.Get_Item($label_id_source)
                
            Add-AwinguLabelToAppServer -session $To -appserverid $server_id -labeltype "labels" -labelid $label_id_dest

            }  

        }
    }


function Copy-AwinguApps {
    param(
        [Parameter(Mandatory=$True)]
        $From,
        [Parameter(Mandatory=$True)]
        $To,
        [Parameter(Mandatory=$True)]
        $LabelMap,
        [Parameter(Mandatory=$True)]
        $IconMap
    )

    Get-AwinguApps -session $From -nobuildinapps | ForEach-Object {

        $this_app = $_ 

        # Find matching icon

        $icon_id_source = Get-AwinguID $this_app.icon
        $icon_id_dest = $IconMap.Get_Item($icon_id_source)
    
        $icon = "/api/appicon/" + $icon_id_dest + "/"

        # Create new App

        if ( $this_app.command -eq "") {

                $this_app.command = "empty"

                }

        $app_id = Add-Awinguapp -session $To `
                                -name $this_app.name `
                                -icon $icon `
                                -description $this_app.description `
                                -protocol $this_app.protocol `
                                -command $this_app.command `
                                -supportsUnicodeKbd $this_app.supportsUnicodeKbd `
                                -startInForeground $this_app.startInForeground
    
        # Attach mediatypes
                             
        $this_app.mediaTypes | ForEach-Object {

            $mediatype_id = Find-AwinguMediaType -session $To -mediatype $_
            Add-AwinguMediaTypeToApp -session $To -appid $app_id -mediatypeid $mediatype_id

            }
    
        # Attach categories

        $this_app.categories | ForEach-Object {

            $category_id = Find-AwinguCategory -session $To -category $_                
            Add-AwinguCategoryToApp -session $To -appid $app_id -categoryid $category_id

            }

        # Attach Labels
                     
        $this_app.labels | ForEach-Object {

            $label_id_source = Get-AwinguID $_.uri
            $label_id_dest = $labelmap.Get_Item($label_id_source)
                
            Add-AwinguLabelToApp -session $To -appid $app_id -labeltype "labels" -labelid $label_id_dest

            }           
    
        # Attach Userlabels
                              
        $this_app.userlabels | ForEach-Object {

            $label_id_source = Get-AwinguID $_.uri
            $label_id_dest = $labelmap.Get_Item($label_id_source)
                
            Add-AwinguLabelToApp -session $To -appid $app_id -labeltype "userlabels" -labelid $label_id_dest

            }           
    
        # Attach ServerLabels
            
        $this_app.serverlabels | ForEach-Object {

            $label_id_source = Get-AwinguID $_.uri
            $label_id_dest = $labelmap.Get_Item($label_id_source)

            Add-AwinguLabelToApp -session $To -appid $app_id -labeltype "serverlabels" -labelid $label_id_dest

            }    

        # Attach autostartlabels

        $this_app.autostartlabels | ForEach-Object {

            $label_id_source = Get-AwinguID $_.uri
            $label_id_dest = $labelmap.Get_Item($label_id_source)

            Add-AwinguLabelToApp -session $To -appid $app_id -labeltype "autostartlabels" -labelid $label_id_dest

            }         
                        
        }
    }



Export-ModuleMember -function * -alias *
