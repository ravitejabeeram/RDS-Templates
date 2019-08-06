<#
.SYNOPSIS
	This is a sample script for to deploy the required resources to execute scaling script in Microsoft Azure Automation Account.
.DESCRIPTION
	This sample script will create the scale script execution required resources in Microsoft Azure. Resources are resourcegroup,automation account,automation account runbook, 
    automation account webhook, workspace customtables and fieldnames, azure schedulerjob.
    Run this PowerShell script in adminstrator mode
    This script depends on two PowerShell modules: AzureRM and AzureAD . To install AzureRM and AzureAD modules execute the following commands. Use "-AllowClobber" parameter if you have more than one version of PowerShell modules installed.
	PS C:\>Install-Module AzureRM  -AllowClobber
    PS C:\>Install-Module AzureAD  -AllowClobber

.PARAMETER TenantAdminCredentials
 Required
 Provide the tenant admin credentials(User must have Owner or Contributor permission at subscription level)
.PARAMETER TenantGroupName
 Required
 Provide the name of the tenant group in the Windows Virtual Desktop deployment.
.PARAMETER TenantName
 Required
 Provide the name of the tenant in the Windows Virtual Desktop deployment.
.PARAMETER HostpoolName
 Required
 Provide the name of the WVD Host Pool.
.PARAMETER peakLoadBalancingType
 Required
 Provide the peakLoadBalancingType. Hostpool session Load Balancing Type in Peak Hours.
.PARAMETER RecurrenceInterval
 Required
 Provide the RecurrenceInterval. Scheduler job will run recurrenceInterval basis, so provide recurrence in minutes.
.PARAMETER AADTenantId
 Required
 Provide Tenant ID of Azure Active Directory.
.PARAMETER SubscriptionId
 Required
 Provide Subscription Id of the Azure.
.PARAMETER BeginPeakTime
 Required
 Provide begin of the peak usage time
.PARAMETER EndPeakTime
 Required
 Provide end of the peak usage time
.PARAMETER TimeDifference
 Required
 Provide the Time difference between local time and UTC, in hours(Example: India Standard Time is +5:30)
.PARAMETER SessionThresholdPerCPU
 Required
 Provide the Maximum number of sessions per CPU threshold used to determine when a new RDSH server needs to be started.
.PARAMETER MinimumNumberOfRDSH
 Required
 Provide the Minimum number of host pool VMs to keep running during off-peak usage time.
.PARAMETER MaintenanceTagName
 Required
 Provide the name of the MaintenanceTagName
.PARAMETER WorkspaceName
 Required
 Provide the name of the WorkspaceName
.PARAMETER LimitSecondsToForceLogOffUser
 Required
 Provide the number of seconds to wait before forcing users to logoff. If 0, don't force users to logoff
.PARAMETER Location
 Required
 Provide the name of the Location to create azure resources. By default location is "South Central US".
.PARAMETER LogOffMessageTitle
 Required
 Provide the Message title sent to a user before forcing logoff
.PARAMETER LogOffMessageBody
 Required
 Provide the Message body to send to a user before forcing logoff

#>
param(
	[Parameter(Mandatory = $true)]
	[pscredential]$TenantAdminCredentials,

	[Parameter(Mandatory = $True)]
	[string]$TenantGroupName,

	[Parameter(Mandatory = $True)]
	[string]$TenantName,

	[Parameter(Mandatory = $True)]
	[string]$HostpoolName,

	[Parameter(Mandatory = $True)]
	[string]$peakLoadBalancingType,

	[Parameter(Mandatory = $True)]
	[int]$RecurrenceInterval,

	[Parameter(Mandatory = $True)]
	[string]$AADTenantId,

	[Parameter(Mandatory = $True)]
	[string]$SubscriptionId,

	[Parameter(Mandatory = $True)]
	$BeginPeakTime,

	[Parameter(Mandatory = $True)]
	$EndPeakTime,

	[Parameter(Mandatory = $True)]
	$TimeDifference,

	[Parameter(Mandatory = $True)]
	[int]$SessionThresholdPerCPU,

	[Parameter(Mandatory = $True)]
	[int]$MinimumNumberOfRDSH,

	[Parameter(Mandatory = $True)]
	[string]$MaintenanceTagName,

	[Parameter(Mandatory = $True)]
	[string]$WorkspaceName,

	[Parameter(Mandatory = $True)]
	[int]$LimitSecondsToForceLogOffUser,

	[Parameter(Mandatory = $True)]
	[string]$Location = "South Central US",

	[Parameter(Mandatory = $True)]
	[string]$LogOffMessageTitle,

	[Parameter(Mandatory = $True)]
	[string]$LogOffMessageBody
)

#Initializing variables
$ResourceGroupName = "WVDAutoScaleResourceGroup"
$AutomationAccountName = "WVDAutoScaleAutomatinAccount"
$JobCollectionName = "WVDAutoScaleSchedulerJobCollection"
$RunbookName = "WVDAutoScaleRunbook"
$WebhookName = "WVDAutoScaleWebhook"
$AzureADApplicationName = "WVDAutoScaleAutomationAccountSvcPrnicipal"
$CredentialsAssetName = "WVDAutoScaleSvcPrincipalAsset"
$RequiredModules = @("Az.Accounts","Microsoft.RDInfra.RDPowershell","OMSIngestionAPI","Az.Compute","Az.Resources","Az.OperationalInsights","Az.Automation","Az.Profile")
$RDBrokerURL = "https://rdbroker.wvd.microsoft.com"

$ScriptRepoLocation = "https://raw.githubusercontent.com/Azure/RDS-Templates/ptg-wvdautoscaling-automation/wvd-templates/wvd-scaling-script/wvdscaling-automation"


#Function to add Required modules to Azure Automation account
function AddingModules-toAutomationAccount {
	param(
		[Parameter(Mandatory = $true)]
		[string]$ResourceGroupName,

		[Parameter(Mandatory = $true)]
		[string]$AutomationAccountName,

		[Parameter(Mandatory = $true)]
		[string]$ModuleName,

		# if not specified latest version will be imported
		[Parameter(Mandatory = $false)]
		[string]$ModuleVersion
	)


	$Url = "https://www.powershellgallery.com/api/v2/Search()?`$filter=IsLatestVersion&searchTerm=%27$ModuleName $ModuleVersion%27&targetFramework=%27%27&includePrerelease=false&`$skip=0&`$top=40"

	$SearchResult = Invoke-RestMethod -Method Get -Uri $Url
	if ($SearchResult.Count -ne 1) {
		$SearchResult = $SearchResult[0]
	}

	if (!$SearchResult) {
		Write-Error "Could not find module '$ModuleName' on PowerShell Gallery."
	}
	elseif ($SearchResult.Count -and $SearchResult.Length -gt 1) {
		Write-Error "Module name '$ModuleName' returned multiple results. Please specify an exact module name."
	}
	else {
		$PackageDetails = Invoke-RestMethod -Method Get -Uri $SearchResult.id

		if (!$ModuleVersion) {
			$ModuleVersion = $PackageDetails.entry.properties.version
		}

		$ModuleContentUrl = "https://www.powershellgallery.com/api/v2/package/$ModuleName/$ModuleVersion"

		# Test if the module/version combination exists
		try {
			Invoke-RestMethod $ModuleContentUrl -ErrorAction Stop | Out-Null
			$Stop = $False
		}
		catch {
			Write-Error "Module with name '$ModuleName' of version '$ModuleVersion' does not exist. Are you sure the version specified is correct?"
			$Stop = $True
		}

		if (!$Stop) {

			# Find the actual blob storage location of the module
			do {
				$ActualUrl = $ModuleContentUrl
				$ModuleContentUrl = (Invoke-WebRequest -Uri $ModuleContentUrl -MaximumRedirection 0 -ErrorAction Ignore).Headers.Location
			} while ($ModuleContentUrl -ne $Null)

			New-AzureRmAutomationModule `
 				-ResourceGroupName $ResourceGroupName `
 				-AutomationAccountName $AutomationAccountName `
 				-Name $ModuleName `
 				-ContentLink $ActualUrl
		}
	}
}
#Authenticate to Azure
try {
	Login-AzureRmAccount -Subscription $SubscriptionId -Credential $TenantAdminCredentials
}
catch {
	$_.Exception
}
#Authenticate to WVD
try {
	Add-RdsAccount -DeploymentUrl $RDBrokerURL -Credential $TenantAdminCredentials
}
catch {
	$_.Exception
}
#Convert to local time to UTC time
$CurrentDateTime = Get-Date
$CurrentDateTime = $CurrentDateTime.ToUniversalTime()


#Check If the resourcegroup exist
$ResourceGroup = Get-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction SilentlyContinue
if (!$ResourceGroup) {
	New-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location -Force -Verbose
	Write-Output "Reaource Group was created with name $ResourceGroupName"
}

#Check if the Automation Account exist
$AutomationAccount = Get-AzureRmAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction SilentlyContinue
if (!$AutomationAccount) {
	New-AzureRmAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -Location $Location -Plan Free -Verbose
	Write-Output "Automation Account was created with name $AutomationAccountName"
}

# Connect to Azure AD
try {
	Write-Output "Connecting Azure AD"
	Connect-AzureAD -Credential $TenantAdminCredentials -Verbose
}
catch {
	$_.Exception
}

#Creating a serviceprincipal and assign the required role assignments at WVD Hostpool level and Subscription level
$ServicePrincipal = Get-AzureADApplication -SearchString $AzureADApplicationName -ErrorAction SilentlyContinue
if (!$ServicePrincipal)
{
	$svcPrincipal = New-AzureADApplication -AvailableToOtherTenants $true -DisplayName $AzureADApplicationName -Verbose
	$svcPrincipalCreds = New-AzureADApplicationPasswordCredential -ObjectId $svcPrincipal.ObjectId
	New-AzureRmADServicePrincipal -ApplicationId $svcPrincipal.AppId
	$secpasswd = ConvertTo-SecureString $svcPrincipalCreds.Value -AsPlainText -Force
	$AppCredentials = New-Object System.Management.Automation.PSCredential ($svcPrincipal.AppId,$secpasswd)
	Start-Sleep 45
	New-AzureRmAutomationCredential -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $CredentialsAssetName -Value $AppCredentials -Verbose
	New-AzureRmRoleAssignment -ApplicationId $svcPrincipal.AppId -RoleDefinitionName "Contributor"
	New-RdsRoleAssignment -RoleDefinitionName "RDS Contributor" -ApplicationId $svcPrincipal.AppId -TenantName $TenantName -HostPoolName $HostpoolName
}

#$Runbook = Get-AzureRmAutomationRunbook -Name $RunbookName -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -ErrorAction SilentlyContinue
#if($Runbook -eq $null){
#Creating a runbook and published the basic Scale script file
$DeploymentStatus = New-AzureRmResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateUri "$ScriptRepoLocation/RunbookCreationTemplate.Json" -DeploymentDebugLogLevel All -existingAutomationAccountName $AutomationAccountName -RunbookName $RunbookName -Force -Verbose
if ($DeploymentStatus.ProvisioningState -eq "Succeeded") {
	$WebhookURI = Get-AzureRmAutomationVariable -Name "WebhookURI" -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -ErrorAction SilentlyContinue
	if (!$WebhookURI) {
		$Webhook = New-AzureRmAutomationWebhook -Name $WebhookName -RunbookName $runbookName -IsEnabled $True -ExpiryTime (Get-Date).AddYears(5) -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Force
		$URIofWebhook = $Webhook.WebhookURI | Out-String
		New-AzureRmAutomationVariable -Name "WebhookURI" -Encrypted $false -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Value $URIofWebhook
		$WebhookURI = Get-AzureRmAutomationVariable -Name "WebhookURI" -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -ErrorAction SilentlyContinue
	}
}
#}
# Required modules imported from Automation Account Modules gallery for Scale Script execution
foreach ($ModuleName in $RequiredModules) {
	$ImportedModule = Get-AzureRmAutomationModule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $ModuleName -ErrorAction SilentlyContinue
	if ($ImportedModule -eq $null) {
		AddingModules-toAutomationAccount -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -ModuleName $ModuleName
		if ($Module -eq "Az.Accounts") {
			Start-Sleep -Seconds 40
		}
	}
}

#Check if the log analytic workspace is exist
$LAWorkspace = Get-AzureRmOperationalInsightsWorkspace | Where-Object { $_.Name -eq $WorkspaceName }
$WorkSpace = Get-AzureRmOperationalInsightsWorkspaceSharedKeys -ResourceGroupName $LAWorkspace.ResourceGroupName -Name $WorkspaceName
$SharedKey = $Workspace.PrimarySharedKey
$CustomerId = (Get-AzureRmOperationalInsightsWorkspace -ResourceGroupName $LAWorkspace.ResourceGroupName -Name $workspaceName).CustomerId.GUID

# Create the function to create the authorization signature
function Build-Signature ($customerId,$sharedKey,$date,$contentLength,$method,$contentType,$resource)
{
	$xHeaders = "x-ms-date:" + $date
	$stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

	$bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
	$keyBytes = [Convert]::FromBase64String($sharedKey)

	$sha256 = New-Object System.Security.Cryptography.HMACSHA256
	$sha256.Key = $keyBytes
	$calculatedHash = $sha256.ComputeHash($bytesToHash)
	$encodedHash = [Convert]::ToBase64String($calculatedHash)
	$authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
	return $authorization
}

# Create the function to create and post the request
function Post-LogAnalyticsData ($customerId,$sharedKey,$body,$logType)
{
	$method = "POST"
	$contentType = "application/json"
	$resource = "/api/logs"
	$rfc1123date = [datetime]::UtcNow.ToString("r")
	$contentLength = $body.Length
	$signature = Build-Signature `
 		-customerId $customerId `
 		-sharedKey $sharedKey `
 		-Date $rfc1123date `
 		-contentLength $contentLength `
 		-FileName $fileName `
 		-Method $method `
 		-ContentType $contentType `
 		-resource $resource
	$uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

	$headers = @{
		"Authorization" = $signature;
		"Log-Type" = $logType;
		"x-ms-date" = $rfc1123date;
		"time-generated-field" = $TimeStampField;
	}

	$response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
	return $response.StatusCode

}

# Specify the name of the record type that you'll be creating
$TenantUsageLogType = "WVDTenantUsage_CL"
$TenantScaleLogType = "WVDTenantScale_CL"

# Specify a field with the created time for the records
$TimeStampField = Get-Date
$TimeStampField = $TimeStampField.GetDateTimeFormats(115)


# Submit the data to the API endpoint

#Custom WVDTenantScale Table
$CustomLogWVDTenantScale = @"
    [
      {
        "hostpoolName":" ",
        "logmessage": " "
      }
    ]
"@

Post-LogAnalyticsData -customerId $CustomerID -sharedKey $SharedKey -Body ([System.Text.Encoding]::UTF8.GetBytes($CustomLogWVDTenantScale)) -logType $TenantScaleLogType
#Custom WVDTenantUsage Table
$CustomLogWVDTenantUsage = @"
    [
      {
        "hostpoolName": " ",
        "numberofRunnigHosts": " ",
        "numberofCores": " "
      }
    ]
"@
Post-LogAnalyticsData -customerId $CustomerID -sharedKey $SharedKey -Body ([System.Text.Encoding]::UTF8.GetBytes($CustomLogWVDTenantUsage)) -logType $TenantUsageLogType


#Creating Azure Scheduler job collection and job
$RequestBody = @{
	"RDBrokerURL" = $RDBrokerURL;
	"AADTenantId" = $AADTenantId;
	"subscriptionid" = $subscriptionid;
	"TimeDifference" = $TimeDifference;
	"TenantGroupName" = $TenantGroupName;
	"TenantName" = $TenantName;
	"HostPoolName" = $HostPoolName;
	"peakLoadBalancingType" = $peakLoadBalancingType;
	"MaintenanceTagName" = $MaintenanceTagName;
	"LogAnalyticsWorkspaceId" = $CustomerId;
	"LogAnalyticsPrimaryKey" = $SharedKey;
	"CredentialAssetName" = $CredentialsAssetName;
	"BeginPeakTime" = $BeginPeakTime;
	"EndPeakTime" = $EndPeakTime;
	"MinimumNumberOfRDSH" = $MinimumNumberOfRDSH;
	"SessionThresholdPerCPU" = $SessionThresholdPerCPU;
	"LimitSecondsToForceLogOffUser" = $LimitSecondsToForceLogOffUser;
	"LogOffMessageTitle" = $LogOffMessageTitle;
	"AutomationAccountName" = $AutomationAccountName;
	"LogOffMessageBody" = $LogOffMessageBody }
$RequestBodyJson = $RequestBody | ConvertTo-Json
$HostpoolName = $HostpoolName.Replace(' ','')
$SchedulerDeployment = New-AzureRmResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateUri "$ScriptRepoLocation/AzureScheduler.json" -JobCollectionName $JobCollectionName -ActionURI $WebhookURI.Value -JobName $HostpoolName-Job -StartTime $CurrentDateTime -EndTime Never -RecurrenceInterval $RecurrenceInterval -ActionSettingsBody $RequestBodyJson -DeploymentDebugLogLevel All -Verbose
