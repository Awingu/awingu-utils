#Detect os version script is executed on
$osversionString = (Get-WmiObject -class Win32_OperatingSystem).Caption
If ($osversionString.Contains('2008')){ $osVersion = '2008'}
Elseif ($osversionString.Contains('2012')){ $osversion = '2012'}
Elseif ($osversionString.Contains('2016')){ $osversion = '2016'}
else { $Host.SetShouldExit(1) }

#function to safely define directory of the script
function Get-ScriptDirectory
{
    $Invocation = (Get-Variable MyInvocation -Scope 1).Value;
    if($Invocation.PSScriptRoot)
    {
        $Invocation.PSScriptRoot;
    }
    Elseif($Invocation.MyCommand.Path)
    {
        Split-Path $Invocation.MyCommand.Path
    }
    else
    {
        $Invocation.InvocationName.Substring(0,$Invocation.InvocationName.LastIndexOf("\"));
    }
}

# Create Folder to store the csv
$scriptDir = Get-ScriptDirectory
$path = "$($scriptdir)\Awingu_Apps"
if (Test-Path $path){
    Remove-item $path -recurse
}
New-Item $path -type directory
#Fetch all info to populate the csv
$tabName = "remoteApps"

#Create Table object
$table = New-Object system.Data.DataTable "$tabName"

#Define Columns
$col1 = New-Object system.Data.DataColumn command,([string])
$col2 = New-Object system.Data.DataColumn name,([string])
$col3 = New-Object system.Data.DataColumn icon,([string])

#Add the Columns
$table.columns.add($col1)
$table.columns.add($col2)
$table.columns.add($col3)


if ($osversion -eq '2008')
{
    Import-Module RemoteDesktopServices -verbose
    cd RDS:
    $remoteapps = Get-ChildItem RemoteApp\RemoteAppPrograms
    ForEach ($remoteapp in $remoteapps) {
        #Create a row
        $row = $table.NewRow()
        $row.alias = $remoteapp.Name
        $row.name = (Get-Item RemoteApp\RemoteAppPrograms\$remoteapp\DisplayName).CurrentValue
        $row.icon = (Get-Item RemoteApp\RemoteAppPrograms\$remoteapp\Iconcontents).CurrentValue
        $table.Rows.Add($row)
    }
}
Elseif ($osversion -eq '2012' -OR $osversion -eq '2016')
{
    $remoteapps = get-rdsessioncollection | get-rdremoteapp
    ForEach ($remoteapp in $remoteapps) {
        #Create a row
        $row = $table.NewRow()
        $row.alias = $remoteapp.ALIAS
        $row.name = $remoteapp.DisplayName
        $row.icon = $remoteapp.IconContents -join ','
        $table.Rows.Add($row)
    }
}


#Dump the table into the csv
$tabCsv = $table | export-csv "$path\remoteapps.csv" -noType
