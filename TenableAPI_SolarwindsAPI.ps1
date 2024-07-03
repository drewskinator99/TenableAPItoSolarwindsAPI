# Program Creator: drewskinator99
# Description: This program uses Tenable API calls to 
#    create text files that contain vulnerability details 
#    for all the assets in Tenable for an organization.
#    Files: 
#       Critical vulnerabilities (all)
#       High vulnerabilities (all)
#       All vulnerabilities
#       All vulnerabilities first seen in the last 6 days
#   The program then makes a call out to the Solarwinds Service Desk 
#   API to create a new incident and then attaches the file that contains
#   the vulnerabilities found within the last 6 days to the new incident.
# Assumptions:
#   The program assumes that you have an API token in both Solarwinds Service Desk
#   and Tenable Vulnerability Management. It also assumes you have saved these 
#   tokens in encrypted CLIXML files.  

#################################################
# Send Error Email Function:
#   Sends an email with an error is triggered in 
#   the script.
#################################################
 function SendErrorEmail {
    [cmdletbinding()]param(
    [Parameter(Mandatory=$true)][string] $fromaddress,
    [Parameter(Mandatory=$true)][string] $smtpServer,
    [Parameter][string[]] $ErrorsFound 
    )       
    $subject = "TenableVM API - Errors Found"
    $bodytext = "TenableVM API - Errors Found.`n`nErrors:`n`n"
    foreach($errr in $ErrorsFound){
        $bodytext += $errr + "`n"
    }
    $toaddress = @("youremailaddress@domain.com")
    Send-Mailmessage -smtpServer $smtpServer -from $fromaddress -to $toaddress  -subject $subject -body $bodytext
}
#################################################
# Send Email Function:
#   Function to send an email when the 
#   script completes without error.
#################################################
function SendEmail {
    [cmdletbinding()]param(
    [Parameter(Mandatory=$true)][string] $fromaddress,
    [Parameter(Mandatory=$true)][string] $smtpServer    
    )
    $subject = "TenableVM API Run Complete"
    $bodytext = "TenableVM API Run Complete. Ticket has been made in Solarwinds."
    $toaddress = @("YourEmail@domain.com" )
    Send-Mailmessage -smtpServer $smtpServer -from $fromaddress -to $toaddress  -subject $subject -body $bodytext
}
#################################################
# Variables
#################################################
$thereAreErrors = $false
$fromaddress = "VulnerabilityManagement@yourdomain.com"
$smtpserver = "smtpServer.local"
$FirstFoundDoc =  "C:\Path\FirstFoundTenableDoc.txt"
$AllVunsDoc = "C:\Path\TenableDoc.txt"
$criticalDoc = "C:\Path\CriticalTenableDoc.txt"
$HighDoc = "C:\Path\HighTenableDoc.txt"
$accesskey = Import-Clixml -Path "C:\Path\XML_PAK.xml"
$secretkey = Import-Clixml -Path "C:\Path\XML_PSK.xml"
$token = Import-Clixml -Path "C:\Path\XML_SWSD.xml"
$logPath = "C:\path\LogFile_" + (Get-Date -Format "MM_dd_yyyy") + ".txt"
$timestamp = Get-Date -Format "MM/dd/yyy hh:mm:ss"
#################################################
try {
    # Check if PowerShell version 7 is running
    $version = (Get-Host | Select-Object Version).Version
    if ($PSVersionTable.PSEdition -eq 'Core' -and  $version -ge 7) {
        $timestamp = Get-Date -Format "MM/dd/yyy hh:mm:ss"
        Write-Output "$timestamp : PowerShell 7 or higher is running." >> $logPath
    } else {
        throw "PowerShell 7 or higher is not running."
            $timestamp = Get-Date -Format "MM/dd/yyy hh:mm:ss"
            Write-Output "$timestamp : Errors $_" >> $logPath
            # Handle the error or fallback logic here
            $arr = @()
            $total = $Error.Count
            $i = 0
            while($i -lt $total){
                $b = $Error[$i].ToString()
                $arr += $b
                $i++
            }
            # if the Error object isn't empty, add the Error content to the email
            if($arr){
                SendErrorEmail  -fromaddress $fromaddress -smtpServer $smtpserver -ErrorsFound $arr
            }
            # if it is empty don't include the Error object
            else{
                SendErrorEmail  -fromaddress $fromaddress -smtpServer $smtpserver 
            }
        Exit -1
    }
}
catch {
    $timestamp = Get-Date -Format "MM/dd/yyy hh:mm:ss"
    Write-Output "$timestamp : Error: $_" >> $logPath
    # Handle the error or fallback logic here
    $arr = @()
    $total = $Error.Count
    $i = 0
    while($i -lt $total){
        $b = $Error[$i].ToString()
        $arr += $b
        $i++
    }
    $timestamp = Get-Date -Format "MM/dd/yyy hh:mm:ss"
    Write-Output "$timestamp : [ERROR] Errors:`n`n $Error`n`n" >> $logPath
    if($arr){
        SendErrorEmail  -fromaddress $fromaddress -smtpServer $smtpserver -ErrorsFound $arr
    }
    else{
        SendErrorEmail  -fromaddress $fromaddress -smtpServer $smtpserver 
    }
}
# params for API call
$URI = "https://cloud.tenable.com/workbenches/assets/vulnerabilities"
$params = @{
    Uri = $URI
    Headers = @{
        "Content-Type" = "application/json"
        "X-ApiKeys" = "accessKey=$accesskey;secretKey=$secretkey"
    }
    Method = 'GET'        
}
# stored the information needed to add to the vulnerability objects for each text file
$vulnsarr = @()
$criticalVulnsArr = @()
$highVulnsArr = @()
# Invoke API
try{
    $returnObj = Invoke-RestMethod @params
}
catch{
    $timestamp = Get-Date -Format "MM/dd/yyy hh:mm:ss"
    Write-Output "$timestamp : [ERROR] Running API Call to gather assets. Exiting." >> $logPath
    SendErrorEmail  -fromaddress $fromaddress -smtpServer $smtpserver  
    Exit -1
}
# Get assets
$assets = $returnObj.assets
# No assets were found so send error email and exit
if(!$returnObj.total_asset_count){
    $timestamp = Get-Date -Format "MM/dd/yyy hh:mm:ss"
    Write-Output "$timestamp : Error: $_" >> $logPath
    # Handle the error or fallback logic here
    $arr = @()
    $total = $Error.Count
    $i = 0
    while($i -lt $total){
        $b = $Error[$i].ToString()
        $arr += $b
        $i++
    }
    $timestamp = Get-Date -Format "MM/dd/yyy hh:mm:ss"
    Write-Output "$timestamp : [ERROR] There were no assets found in Tenable VM. Errors:`n`n $Error`n`n" >> $logPath
    if($arr){
        SendErrorEmail  -fromaddress $fromaddress -smtpServer $smtpserver -ErrorsFound $arr
    }
    else{
        SendErrorEmail  -fromaddress $fromaddress -smtpServer $smtpserver 
    }
    Exit -1
}
$URI = 'https://cloud.tenable.com'
# variables used to determine if total vulnerability banner should be printed
$firstTimeListingAssetForHigh = $true
$firstTimeListingAssetForCritical = $true
$firstTimeListingAssetForFirsts = $true
# print vulnerabilities for each asset
foreach($asset in $assets){
    # first time asset is found flags
    $firstTimeListingAssetForHigh = $true
    $firstTimeListingAssetForCritical = $true
    $firstTimeListingAssetForFirsts = $true
    $id = $asset.id
    # set parameters for API call
    $paramsVuln = @{
        Uri = $URI + "/workbenches/assets/$id" + "/vulnerabilities"
        Headers = @{
            "Content-Type" = "application/json"
            "X-ApiKeys" = "accessKey=$accesskey;secretKey=$secretkey"
        }
        Method = 'GET'
    }                
    # name the asset 
    if($asset.netbios_name){$assetname = $asset.netbios_name}
    elseif($asset.fqdn){$assetname = $asset.fqdn}         
    else{$assetname = $asset.ipv4}
    # create severity object to display counts of vulnerabilites by severity 
    $severities = $asset.severities
    $severityObjArr = @()
    foreach($severity in $severities){
        $severityObj = [pscustomobject]@{
            Name = $severity.Name 
            Count = $severity.Count
        }
        $severityObjArr += $severityObj
    } # end of severity for loop
    # add asset to "all vulnerabilities" File
    Write-Output "---------------------------------`nAsset Name:`t$assetname`n---------------------------------" >> $AllVunsDoc
    Write-Output "`nTotal Vulnerability Counts:`n----------------------------" >> $AllVunsDoc
    $severityObjArr | Format-Table >> $AllVunsDoc
    # Debug: Print asset to screen
    $assetname   
    # invoke API call for each asset to get vulnerabilities
    try{
        $vulns = Invoke-RestMethod @paramsVuln
    }
    catch{
        $timestamp = Get-Date -Format "MM/dd/yyy hh:mm:ss"
        Write-Output "$timestamp : [ERROR] Running API Call to gather vulnerabilities for $assetname." >> $logPath
        $thereAreErrors = $true  
        Continue
    }
    # prepare vulnerability object for each asset
    $vulnerabilities = $vulns.vulnerabilities | Where-Object {$_.severity -gt 0}
    $vulnerabilityObjectArr = @()
    Write-Output "`nVulnerability Details:`n----------------------" >> $AllVunsDoc
    # for each asset, run API to get vulnerabilities and print them
    foreach($vulnerability in $vulnerabilities){
        $sev = $vulnerability.severity
        if($sev -eq 4){$SevLabel = "Critical"}
        elseif($sev -eq 3){$SevLabel = "High"}
        elseif($sev -eq 2){$SevLabel = "Medium"}
        elseif($sev -eq 1){$SevLabel = "Low"}
        $accepted = "Not Accepted"
        if($vulnerability.accepted_count){
            $accepted = 'Accepted'
        }           
        $pluginid = $vulnerability.plugin_id
        $pluginParams = @{
            Uri = $URI + "/workbenches/vulnerabilities/$pluginid" + "/info"
            Headers = @{
                "Content-Type" = "application/json"
                "X-ApiKeys" = "accessKey=$accesskey;secretKey=$secretkey"
            }
            Method = 'GET'
        }
        # Invoke API
        try{
            $PluginDetailsReturnObject = Invoke-RestMethod @pluginParams
        }
        catch{
            $timestamp = Get-Date -Format "MM/dd/yyy hh:mm:ss"
            Write-Output "$timestamp : [ERROR] Running API Call to gather vulnerabilities for plugin for id: $pluginid." >> $logPath
            $thereAreErrors = $true  
            Continue
        }
        $pluginDetails = $PluginDetailsReturnObject.info 
        $date = ($asset.last_seen)
        $firstseen = ($pluginDetails.discovery).seen_first
        $firstseenDate = Get-date $firstseen
        $compareDate = (Get-Date).AddDays(-6)
        # For each vulnerability, grab the details of the vulnerability and store it in object   
        $vulnerabilityObject = [pscustomobject]@{
            HostName = $assetname               
            Name = $vulnerability.plugin_name
            Severity = $SevLabel
            Plugin_Id = $vulnerability.plugin_id
            First_Seen = $firstseen
            Last_Seen = $asset.last_seen                  
            Accepted = $accepted
            VPR_Score = $vulnerability.vpr_score
            CVSS_Score = $vulnerability.cvss3_base_score
            Vulnerability_Frequency = $vulnerability.count
            Description = $pluginDetails.description
            Solution = $pluginDetails.solution
            ExploitAvailable = ($pluginDetails.vulnerability_information).exploit_available
            ExploitEase = ($pluginDetails.vulnerability_information).exploitability_ease
            PatchPublicationDate = ($pluginDetails.vulnerability_information).patch_publication_date
        }
        # this was found in the last 6 days
        if(!($firstseenDate -lt $compareDate)){
            if($firstTimeListingAssetForFirsts){
                Write-Output "---------------------------------`nAsset Name:`t$assetname`n---------------------------------" >> $FirstFoundDoc
                Write-Output "`nTotal Vulnerability Counts:`n----------------------------" >> $FirstFoundDoc
                $severityObjArr | ft >> $FirstFoundDoc
                Write-Output "`nVulnerability Details:`n----------------------" >> $FirstFoundDoc
            }
            # print vulnerabilities to file   
            $vulnerabilityObject >> $FirstFoundDoc
            # flag for displaying vulnerability summary table               
            $firstTimeListingAssetForFirsts = $false
        }
        # Add to critical array and print out to file
        if($vulnerability.severity -eq 4 ){
            if($firstTimeListingAssetForCritical){
                Write-Output "---------------------------------`nAsset Name:`t$assetname`n---------------------------------" >> $criticalDoc
                Write-Output "`nTotal Vulnerability Counts:`n----------------------------" >> $criticalDoc
                $severityObjArr | ft >> $criticalDoc
                Write-Output "`nVulnerability Details:`n----------------------" >> $criticalDoc
            }
            # add critical vulnerability to critical file
            $vulnerabilityObject >> $criticalDoc
            $criticalVulnsArr += $vulnerabilityObject
            $firstTimeListingAssetForCritical = $false
        }
        # Add to High Array and print out to file
        elseif($vulnerability.severity -eq 3 ){
            if($firstTimeListingAssetForHigh){
                Write-Output "---------------------------------`nAsset Name:`t$assetname`n---------------------------------" >> $HighDoc
                Write-Output "`nTotal Vulnerability Counts:`n----------------------------" >> $HighDoc
                $severityObjArr | ft >> $HighDoc
                Write-Output "`nVulnerability Details:`n----------------------" >> $HighDoc
            }
            $vulnerabilityObject >> $HighDoc
            $criticalVulnsArr += $vulnerabilityObject
            $highVulnsArr += $vulnerabilityObject
            $firstTimeListingAssetForHigh = $false
        }
        # print to file
        $vulnerabilityObject >> $AllVunsDoc
        #add vulnerability to array
        $vulnerabilityObjectArr += $vulnerabilityObject             
    } # end of vulnerability for loop
          
    $vulnerabilitiescount = $vulns.total_vulnerability_count
    # create an object that stores all the data for an asset for
    # optional use later     
    $object = [pscustomobject]@{
        Vulnerabilities = $vulnerabilityObjectArr             
        asset = $assetname
        Severities = $severityObjArr
        Total_Count = $vulnerabilitiescount
        Plugins = $pluginarr
    }
    $vulnsarr += $object         
}

##########################
# SOLARWINDS API CALLS 
##########################

# Title on incident in Solarwinds
$date = Get-Date -Format "MMMM dd yyyy"
$title = "New Vulnerabilities Found Starting Week of " + $date + ":"
$SolarwindsUrl = 'https://api.samanage.com/incidents'  
$headers = @{
    'X-Samanage-Authorization' = "Bearer $token"
    Accept =  "application/json"        
}
$paramsnew = @{      
    incident = @{    
        'name' = $title
        'description' = "Please see the attached file for details"
        category = @{
            name = "Security" 
        }
        subcategory = @{
            name = "Vulnerability Management" 
        }
        assignee_id="9999999"       
    }       
}
# Invoke API
try{
    $result =  Invoke-RestMethod -uri $SolarwindsUrl -Method POST -Body ($paramsnew | ConvertTo-Json ) -ContentType "application/json" -Headers $headers 
}
catch{
    $timestamp = Get-Date -Format "MM/dd/yyy hh:mm:ss"
    Write-Output "$timestamp : [ERROR] Running API Call to create Solarwinds Incident. Exiting." >> $logPath
    SendErrorEmail  -fromaddress $fromaddress -smtpServer $smtpserver  
    Exit -1
}
# Get incident id
$id = $result.id
# attach a file to the incident created in the previous POST
$headers = @{
    'X-Samanage-Authorization' = "Bearer $token"                
}
$uri = 'https://api.samanage.com/attachments'          
# create file object
$file = @{            
     "file[attachable_type]" = 'Incident'
     "file[attachable_id]" = $id
     "file[attachment]" = (get-item -path $FirstFoundDoc)           
}    
# Invoke API  
try{
    $filteresult = Invoke-RestMethod -Uri $uri -form $file -ContentType 'multipart/form-data'  -Method Post -Headers $headers
}
catch{
    $timestamp = Get-Date -Format "MM/dd/yyy hh:mm:ss"
    Write-Output "$timestamp : [ERROR] Running API Call to attach file to Solarwinds Incident. Exiting." >> $logPath
    SendErrorEmail  -fromaddress $fromaddress -smtpServer $smtpserver  
    Exit -1
}
# debug
$filteresult
# there were errors, send error email
if($thereAreErrors){
    # Handle the error or fallback logic here
    $arr = @()
    $total = $Error.Count
    $i = 0
    while($i -lt $total){
        $b = $Error[$i].ToString()
        $arr += $b
        $i++
    }
    $timestamp = Get-Date -Format "MM/dd/yyy hh:mm:ss"
    if($arr){
        SendErrorEmail  -fromaddress $fromaddress -smtpServer $smtpserver -ErrorsFound $arr
    }
    else{
        SendErrorEmail  -fromaddress $fromaddress -smtpServer $smtpserver 
    }
}
# There were no errors, send email
else{
    SendEmail -fromaddress $fromaddress -smtpServer $smtpserver   
}
# delete files for next run to create files with with only new data in them
if(Test-Path $FirstFoundDoc){Remove-Item $FirstFoundDoc -Force -confirm:$false}
if(Test-Path $HighDoc){Remove-Item $HighDoc -Force -confirm:$false}
if(Test-Path $criticalDoc){Remove-Item $criticalDoc -Force -confirm:$false}