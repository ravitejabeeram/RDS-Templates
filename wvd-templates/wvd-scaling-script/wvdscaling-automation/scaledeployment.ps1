<#
.SYNOPSIS
	This is a sample script for to deploy the required resources to execute scaling script in Microsoft Azure Automation Account.
.DESCRIPTION
	This sample script will create the scale script execution required resources in Microsoft Azure. Resources are resourcegroup,automation account,automation account runbook, 
    automation account webhook, workspace customtables and fieldnames, azure schedulerjob.
    Run this PowerShell script in adminstrator mode
    This script depends on two PowerShell modules: AzureRm and AzureAD . To install AzureRm and AzureAD modules execute the following commands. Use "-AllowClobber" parameter if you have more than one version of PowerShell modules installed.
	PS C:\>Install-Module AzureRm  -AllowClobber
    PS C:\>Install-Module AzureAD  -AllowClobber

.PARAMETER AzureADApplicationId
 Required
 Provide Azure AD Application Id and it must have 'Contributor' role at Subscription, "Azure Service Management" Api Permission and 'RDS Contributor/RDS Owner' at WVD Tenant.
.PARAMETER AzureAdApplicationSecret
 Required
 Provide Azure AD Application Secret value.
.PARAMETER TenantGroupName
 Required
 Provide the name of the tenant group in the Windows Virtual Desktop deployment.
.PARAMETER TenantName
 Required
 Provide the name of the tenant in the Windows Virtual Desktop deployment.
.PARAMETER HostpoolName
 Required
 Provide the name of the WVD Host Pool.
.PARAMETER PeakLoadBalancingType
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
 Provide the name of the Location to create azure resources.
.PARAMETER LogOffMessageTitle
 Required
 Provide the Message title sent to a user before forcing logoff
.PARAMETER LogOffMessageBody
 Required
 Provide the Message body to send to a user before forcing logoff
 Example: .\scaledeployment.ps1  -AzureADApplicationId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -AzureAdApplicationSecret "Youre Azure AD Application Secret" -AADTenantID "Your Azure TenantID" -SubscriptionID "Your Azure SubscriptionID" -TenantGroupName "Name of the WVD Tenant Group Name" ` 
 -TenantName "Name of the WVD Tenant Name" -HostPoolName "Name of the HostPoolName" -PeakLoadBalancingType "Load balancing type in Peak hours" -MaintenanceTagName "Name of the Tag Name" -RecurrenceInterval "Repeat job every and select the appropriate period of time in minutes (Ex. 15)" ` 
 -WorkspaceName "Name of the Workspace" -BeginPeakTime "9:00" -EndPeakTime "18:00" -TimeDifference "+5:30" -SessionThresholdPerCPU 6 -MinimumNumberOfRDSH 2 -LimitSecondsToForceLogOffUser 20 –LogOffMessageTitle "System Under Maintenance" -LogOffMessageBody "Please save your work and logoff!" `
 –Location "Central US"

#>
param(
	[Parameter(mandatory = $True)]
	[string]$AzureADApplicationId,

	[Parameter(mandatory = $True)]
	[securestring]$AzureADApplicationSecret,

	[Parameter(mandatory = $True)]
	[string]$TenantGroupName,

	[Parameter(mandatory = $True)]
	[string]$TenantName,

	[Parameter(mandatory = $True)]
	[string]$HostpoolName,

	[Parameter(mandatory = $True)]
	[string]$PeakLoadBalancingType,

	[Parameter(mandatory = $True)]
	[int]$RecurrenceInterval,

	[Parameter(mandatory = $True)]
	[string]$AADTenantId,

	[Parameter(mandatory = $True)]
	[string]$SubscriptionId,

	[Parameter(mandatory = $True)]
	$BeginPeakTime,

	[Parameter(mandatory = $True)]
	$EndPeakTime,

	[Parameter(mandatory = $True)]
	$TimeDifference,

	[Parameter(mandatory = $True)]
	[int]$SessionThresholdPerCPU,

	[Parameter(mandatory = $True)]
	[int]$MinimumNumberOfRDSH,

	[Parameter(mandatory = $True)]
	[string]$MaintenanceTagName,

	[Parameter(mandatory = $True)]
	[string]$WorkspaceName,

	[Parameter(mandatory = $True)]
	[int]$LimitSecondsToForceLogOffUser,

	[Parameter(mandatory = $True)]
	[string]$Location,

	[Parameter(mandatory = $True)]
	[string]$LogOffMessageTitle,

	[Parameter(mandatory = $True)]
	[string]$LogOffMessageBody
)
#Initializing variables
$ResourceGroupName = "WVDAutoScaleResourceGroup"
$AutomationAccountName = "WVDAutoScaleAutomationAccount"
$JobCollectionName = "WVDAutoScaleSchedulerJobCollection"
$RunbookName = "WVDAutoScaleRunbook"
$WebhookName = "WVDAutoScaleWebhook"
$CredentialsAssetName = "WVDAutoScaleSvcPrincipalAsset"
$RequiredModules = @(
	[pscustomobject]@{ ModuleName = 'AzureRM.Profile'; ModuleVersion = '5.8.3' }
	[pscustomobject]@{ ModuleName = 'Microsoft.RDInfra.RDPowershell'; ModuleVersion = '1.0.833' }
	[pscustomobject]@{ ModuleName = 'OMSIngestionAPI'; ModuleVersion = '1.6.0' }
	[pscustomobject]@{ ModuleName = 'AzureRM.Compute'; ModuleVersion = '5.9.1' }
	[pscustomobject]@{ ModuleName = 'AzureRM.Resources'; ModuleVersion = '6.7.3' }
	[pscustomobject]@{ ModuleName = 'AzureRM.Automation'; ModuleVersion = '6.1.1' }
)
$RDBrokerURL = "https://rdbroker.wvd.microsoft.com"
$ScriptRepoLocation = "https://raw.githubusercontent.com/Azure/RDS-Templates/ptg-wvdautoscaling-automation/wvd-templates/wvd-scaling-script/wvdscaling-automation"
$ServicePrincipalCredentials = New-Object System.Management.Automation.PSCredential ($AzureADApplicationID,$AzureADApplicationSecret)

#Function to add Required modules to Azure Automation account
function AddingModules-toAutomationAccount {
	param(
		[Parameter(mandatory = $true)]
		[string]$ResourceGroupName,

		[Parameter(mandatory = $true)]
		[string]$AutomationAccountName,

		[Parameter(mandatory = $true)]
		[string]$ModuleName,

		# if not specified latest version will be imported
		[Parameter(mandatory = $false)]
		[string]$ModuleVersion
	)


	$Url = "https://www.powershellgallery.com/api/v2/Search()?`$filter=IsLatestVersion&searchTerm=%27$ModuleName $ModuleVersion%27&targetFramework=%27%27&includePrerelease=false&`$skip=0&`$top=40"

	[array]$SearchResult = Invoke-RestMethod -Method Get -Uri $Url
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
		$PackageDetails = Invoke-RestMethod -Method Get -Uri $SearchResult.Id

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
				$ModuleContentUrl = (Invoke-WebRequest -Uri $ModuleContentUrl -MaximumRedirection 0 -UseBasicParsing -ErrorAction Ignore).Headers.Location
			} while ($ModuleContentUrl -ne $Null)

			New-AzureRmAutomationModule `
 				-ResourceGroupName $ResourceGroupName `
 				-AutomationAccountName $AutomationAccountName `
 				-Name $ModuleName `
 				-ContentLink $ActualUrl
		}
	}
}

#Function to check if the module is imported
function Check-IfModuleIsImported {
	param(
		[Parameter(mandatory = $true)]
		[string]$ResourceGroupName,

		[Parameter(mandatory = $true)]
		[string]$AutomationAccountName,

		[Parameter(mandatory = $true)]
		[string]$ModuleName
	)

	$IsModuleImported = $false
	while (!$IsModuleImported) {
		$IsModule = Get-AzureRmAutomationModule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $ModuleName -ErrorAction SilentlyContinue
		if ($IsModule.ProvisioningState -eq "Succeeded") {
			$IsModuleImported = $true
			Write-Output "Successfully $ModuleName module imported into Automation Account Modules..."
		}
		else {
			Write-Output "Waiting for to import module $ModuleName into Automation Account Modules ..."
		}
	}
}
#Authenticate to Azure
try {
	$AZAuthentication = Login-AzureRmAccount -Subscription $SubscriptionId -Tenant $AADTenantId -Credential $ServicePrincipalCredentials -ServicePrincipal
}
catch {
	Write-Output "Failed to authenticate Azure: $($_.exception.message)"
	throw $_
	exit
}
$AzObj = $AZAuthentication | Out-String
Write-Output "Authenticating as service principal for Azure. Result: `n$AzObj"

#Convert to local time to UTC time
$CurrentDateTime = Get-Date
$CurrentDateTime = $CurrentDateTime.ToUniversalTime()


#Check If the resourcegroup exist
$ResourceGroup = Get-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction SilentlyContinue
if (!$ResourceGroup) {
	New-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location -Force -Verbose
	Write-Output "Resource Group was created with name $ResourceGroupName"
}

#Check if the Automation Account exist
$AutomationAccount = Get-AzureRmAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -ErrorAction SilentlyContinue
if (!$AutomationAccount) {
	New-AzureRmAutomationAccount -ResourceGroupName $ResourceGroupName -Name $AutomationAccountName -Location $Location -Plan Free -Verbose
	Write-Output "Automation Account was created with name $AutomationAccountName"
}

#$Runbook = Get-AzureRmAutomationRunbook -Name $RunbookName -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -ErrorAction SilentlyContinue
#if($Runbook -eq $null){
#Creating a runbook and published the basic Scale script file
$DeploymentStatus = New-AzureRmResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateUri "$ScriptRepoLocation/runbookCreationTemplate.json" -DeploymentDebugLogLevel All -existingAutomationAccountName $AutomationAccountName -RunbookName $RunbookName -Force -Verbose
if ($DeploymentStatus.ProvisioningState -eq "Succeeded") {

	#Check if the Webhook URI exists in automation variable
	$WebhookURI = Get-AzureRmAutomationVariable -Name "WebhookURI" -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -ErrorAction SilentlyContinue
	if (!$WebhookURI) {
		$Webhook = New-AzureRmAutomationWebhook -Name $WebhookName -RunbookName $runbookName -IsEnabled $True -ExpiryTime (Get-Date).AddYears(5) -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Force
		Write-Output "Automation Account Webhook is created with name '$WebhookName'"
		$URIofWebhook = $Webhook.WebhookURI | Out-String
		New-AzureRmAutomationVariable -Name "WebhookURI" -Encrypted $false -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Value $URIofWebhook
		Write-Output "Webhook URI stored in Azure Automation Acccount variables"
		$WebhookURI = Get-AzureRmAutomationVariable -Name "WebhookURI" -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -ErrorAction SilentlyContinue
		New-AzureRmAutomationCredential -AutomationAccountName $AutomationAccountName -ResourceGroupName $ResourceGroupName -Name $CredentialsAssetName -Value $ServicePrincipalCredentials -Verbose
		Write-Output "Service principal credentials stored into Azure Automation Account credentials asset"
	}
}
#}
# Required modules imported from Automation Account Modules gallery for Scale Script execution
foreach ($Module in $RequiredModules) {
	# Check if the required modules are imported 
	$ImportedModule = Get-AzureRmAutomationModule -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $Module.ModuleName -ErrorAction SilentlyContinue
	if ($ImportedModule -eq $Null) {
		AddingModules-toAutomationAccount -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -ModuleName $Module.ModuleName
		Check-IfModuleIsImported -ModuleName $Module.ModuleName -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName
	}
	elseif ($ImportedModule.version -ne $Module.ModuleVersion) {
		AddingModules-toAutomationAccount -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -ModuleName $Module.ModuleName
		Check-IfModuleIsImported -ModuleName $Module.ModuleName -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName
	}
}

#Check if the log analytic workspace is exist
$LAWorkspace = Get-AzureRmOperationalInsightsWorkspace | Where-Object { $_.Name -eq $WorkspaceName }
$WorkSpace = Get-AzureRmOperationalInsightsWorkspaceSharedKeys -ResourceGroupName $LAWorkspace.ResourceGroupName -Name $WorkspaceName
$LogAnalyticsPrimaryKey = $Workspace.PrimarySharedKey
$LogAnalyticsWorkspaceId = (Get-AzureRmOperationalInsightsWorkspace -ResourceGroupName $LAWorkspace.ResourceGroupName -Name $workspaceName).CustomerId.GUID

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

Post-LogAnalyticsData -customerId $LogAnalyticsWorkspaceId -sharedKey $LogAnalyticsPrimaryKey -Body ([System.Text.Encoding]::UTF8.GetBytes($CustomLogWVDTenantScale)) -logType $TenantScaleLogType

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
$SchedulerDeployment = New-AzureRmResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateUri "$ScriptRepoLocation/azureScheduler.json" -JobCollectionName $JobCollectionName -ActionURI $WebhookURI.Value -JobName $HostpoolName-Job -StartTime $CurrentDateTime -EndTime Never -RecurrenceInterval $RecurrenceInterval -ActionSettingsBody $RequestBodyJson -DeploymentDebugLogLevel All -Verbose
if ($SchedulerDeployment) {
	Write-Output "$HostpoolName-job Azure Scheduler job was created successfully"
}