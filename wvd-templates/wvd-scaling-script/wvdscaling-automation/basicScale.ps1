param(
	[Parameter(Mandatory = $false)]
	[object]$WebHookData
)
# If runbook was called from Webhook, WebhookData will not be null.
if ($WebHookData) {

	# Collect properties of WebhookData
	$WebhookName = $WebHookData.WebhookName
	$WebhookHeaders = $WebHookData.RequestHeader
	$WebhookBody = $WebHookData.RequestBody

	# Collect individual headers. Input converted from JSON.
	$From = $WebhookHeaders.From
	$Input = (ConvertFrom-Json -InputObject $WebhookBody)
	Write-Verbose "WebhookBody: $Input"
	Write-Output -InputObject ('Runbook started from webhook {0} by {1}.' -f $WebhookName,$From)
}
else
{
	Write-Error -Message 'Runbook was not started from Webhook' -ErrorAction stop
}
$AADTenantId = $Input.AADTenantId
$SubscriptionID = $Input.SubscriptionID
$TenantGroupName = $Input.TenantGroupName
$TenantName = $Input.TenantName
$HostpoolName = $Input.HostpoolName
$PeakLoadBalancingType = $Input.PeakLoadBalancingType
$BeginPeakTime = $Input.BeginPeakTime
$EndPeakTime = $Input.EndPeakTime
$TimeDifference = $Input.TimeDifference
$SessionThresholdPerCPU = $Input.SessionThresholdPerCPU
$MinimumNumberOfRDSH = $Input.MinimumNumberOfRDSH
$LimitSecondsToForceLogOffUser = $Input.LimitSecondsToForceLogOffUser
$LogOffMessageTitle = $Input.LogOffMessageTitle
$LogOffMessageBody = $Input.LogOffMessageBody
$MaintenanceTagName = $Input.MaintenanceTagName
$CredentialAssetName = $Input.CredentialAssetName
$LogAnalyticsWorkspaceId = $Input.LogAnalyticsWorkspaceId
$LogAnalyticsPrimaryKey = $Input.LogAnalyticsPrimaryKey
$RDBrokerURL = $Input.RDBrokerURL
$AutomationAccountName = $Input.AutomationAccountName

Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope Process -Force -Confirm:$false
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force -Confirm:$false

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Collect the credentials from Azure Automation Account Assets
$Credentials = Get-AutomationPSCredential -Name $CredentialAssetName

#Authenticating to Azure
try {
	$AZAuthentication = Add-AzAccount -Credential $Credentials -TenantId $AADTenantId -SubscriptionId $SubscriptionID -ServicePrincipal
	#Select Azure Subscription
	$AzSubscription = Select-AzSubscription -Subscription $SubscriptionID -Tenant $AADTenantID -Force
}
catch {
	Write-Output "Failed to authenticate Azure: $($_.exception.message)" "Error"
	exit
}
$AzObj = $authentication | Out-String
Write-Output "Authenticating as standard account for WVD. Result: `n$AzObj"

#Authenticating to WVD
try {
	$WVDAuthentication = Add-RdsAccount -DeploymentUrl $RDBrokerURL -Credential $Credentials -TenantId $AADTenantId -ServicePrincipal
}
catch {
	Write-Output "Failed to authenticate WVD: $($_.exception.message)" "Error"
	exit
}
$WVDObj = $WVDAuthentication | Out-String
Write-Output "Authenticating as standard account for WVD. Result: `n$WVDObj"

<#
.Description
Helper functions
#>
#Function to convert from UTC to Local time
function Convert-UTCtoLocalTime
{
	param(
		$TimeDifferenceInHours
	)

	$UniversalTime = (Get-Date).ToUniversalTime()
	$TimeDifferenceMinutes = 0
	if ($TimeDifferenceInHours -match ":") {
		$TimeDifferenceHours = $TimeDifferenceInHours.Split(":")[0]
		$TimeDifferenceMinutes = $TimeDifferenceInHours.Split(":")[1]
	}
	else {
		$TimeDifferenceHours = $TimeDifferenceInHours
	}
	#Azure is using UTC time, justify it to the local time
	$ConvertedTime = $UniversalTime.AddHours($TimeDifferenceHours).AddMinutes($TimeDifferenceMinutes)
	return $ConvertedTime
}
# Function for to add logs to log analytics workspace
function Add-LogEntry
{
	param(
		[Object]$LogMessage,
		[string]$LogAnalyticsWorkspaceId,
		[string]$LogAnalyticsPrimaryKey,
		[string]$LogType,
		$TimeDifferenceInHours
	)

	if ($LogAnalyticsWorkspaceId -ne $null) {

		foreach ($Key in $LogMessage.Keys) {
			switch ($Key.Substring($Key.Length - 2)) {
				'_s' { $sep = '"'; $trim = $Key.Length - 2 }
				'_t' { $sep = '"'; $trim = $Key.Length - 2 }
				'_b' { $sep = ''; $trim = $Key.Length - 2 }
				'_d' { $sep = ''; $trim = $Key.Length - 2 }
				'_g' { $sep = '"'; $trim = $Key.Length - 2 }
				default { $sep = '"'; $trim = $Key.Length }
			}
			$LogMessage = $LogMessage + '"' + $Key.Substring(0,$trim) + '":' + $sep + $LogMessage.Item($Key) + $sep + ','
		}
		$TimeStamp = ConvertUTCtoLocal -TimeDifferenceInHours $TimeDifferenceInHours
		$LogMessage = $LogMessage + '"TimeStamp":"' + $timestamp + '"'

		Write-Verbose "LogData: $($LogMessage)"
		$json = "{$($LogMessage)}"

		$PostResult = Send-OMSAPIIngestionFile -customerId $LogAnalyticsWorkspaceId -sharedKey $LogAnalyticsPrimaryKey -Body "$json" -logType $LogType -TimeStampField "TimeStamp"
		Write-Verbose "PostResult: $($PostResult)"
		if ($PostResult -ne "Accepted") {
			Write-Error "Error posting to OMS - $PostResult"
		}
	}
}
# Function to update load balancer type based on PeakloadbalancingType
function Updating-LoadBalancingTypeInPeakHours
{
	param(
		[string]$HostpoolLoadbalancerType,
		[string]$PeakLoadBalancingType,
		[string]$TenantName,
		[string]$HostpoolName,
		[int]$MaxSessionLimitValue
	)
	if ($HostpoolInfo.LoadBalancerType -ne $PeakLoadBalancingType) {
		Write-Output "Changing Hostpool Load Balance Type:$PeakLoadBalancingType Current Date Time is: $CurrentDateTime"
		if ($PeakLoadBalancingType -eq "DepthFirst") {
			Set-RdsHostPool -TenantName $TenantName -Name $HostpoolName -DepthFirstLoadBalancer -MaxSessionLimit $HostpoolInfo.MaxSessionLimit
		}
		else {
			Set-RdsHostPool -TenantName $TenantName -Name $HostpoolName -BreadthFirstLoadBalancer -MaxSessionLimit $HostpoolInfo.MaxSessionLimit
		}
		Write-Output "Hostpool Load balancer Type in Session Load Balancing Peak Hours is '$PeakLoadBalancingType Load Balancing'"
	}
}
# Function to update load balancer type in off peak hours
function Updating-LoadBalancingTypeINOffPeakHours
{
	param(
		[string]$HostpoolLoadbalancerType,
		[string]$PeakloadbalancingType,
		[string]$TenantName,
		[string]$HostpoolName,
		[int]$MaxSessionLimitValue
	)
	if ($HostpoolInfo.LoadBalancerType -eq $PeakLoadBalancingType) {
		Write-Output "Changing Hostpool Load Balance Type in off peak hours Current Date Time is: $CurrentDateTime"
		if ($hostpoolinfo.LoadBalancerType -ne "DepthFirst") {
			$LoadBalanceType = Set-RdsHostPool -TenantName $TenantName -Name $HostpoolName -DepthFirstLoadBalancer -MaxSessionLimit $MaxSessionLimitValue

		} else {
			$LoadBalanceType = Set-RdsHostPool -TenantName $TenantName -Name $HostpoolName -BreadthFirstLoadBalancer -MaxSessionLimit $MaxSessionLimitValue
		}
		$LoadBalancerType = $LoadBalanceType.LoadBalancerType
		Write-Output "Hostpool Load balancer Type in off Peak Hours is '$LoadBalancerType Load Balancing'"
	}
}
# Function to Check if the hostpool have sessionhosts
function Check-IfHostpoolHaveSessionHosts
{
	param(
		[string]$TenantName,
		[string]$HostpoolName
	)
	$ListOfSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -ErrorAction SilentlyContinue | Sort-Object SessionHostName
	if ($ListOfSessionHosts -eq $null) {
		Write-Output "Sessionhosts does not exist in the Hostpool of '$HostpoolName'. Ensure that hostpool have hosts or not?."
		exit
	}
	return $ListOfSessionHosts
}
#Function to Check if the session host is allowing new connections
function Check-ForAllowNewConnections
{
	param(
		[string]$TenantName,
		[string]$HostpoolName,
		[string]$SessionHostName
	)

	# Check if the session host is allowing new connections
	$StateOftheSessionHost = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHostName
	if (!($StateOftheSessionHost.AllowNewSession)) {
		Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHostName -AllowNewSession $true
	}

}
# Check if the host is enabled maintenance tag              
function Check-IfSessionHostInMaintenance
{
	param(
		[string]$VMName
	)
	# Check the session host is in maintenance
	$VmInfo = Get-AzVM | Where-Object { $_.Name -eq $VMName }
	if ($VmInfo.Tags.Keys -contains $MaintenanceTagName) {
		Write-Output "Session Host is in Maintenance: $VMName"
		continue
	}
}

# Start the Session Host 
function Start-SessionHost
{
	param(
		[string]$VMName
	)
	try {
		Write-Output "Starting Azure VM: $VMName and waiting for it to complete ..."
		Get-AzVM | Where-Object { $_.Name -eq $VMName } | Start-AzVM
	}
	catch {
		Write-Output "Failed to start Azure VM: $($VMName) with error: $($_.exception.message)"
		exit
	}

}
# Stop the Session Host
function Stop-SessionHost
{
	param(
		[string]$VMName
	)
	try {
		Write-Output "Stopping Azure VM: $VMName and waiting for it to complete ..."
		Get-AzVM | Where-Object { $_.Name -eq $VMName } | Stop-AzVM -Force
	}
	catch {
		Write-Output "Failed to stop Azure VM: $VMName with error: $_.exception.message"
		exit
	}
}
# Check if the Session host is available
function Check-IfSessionHostIsAvailable
{
	param(
		[string]$TenantName,
		[string]$HostpoolName,
		[string]$SessionHostName
	)
	$IsHostAvailable = $false
	while (!$IsHostAvailable) {
		$SessionHostStatus = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHostName
		if ($SessionHostStatus.Status -eq "Available") {
			$IsHostAvailable = $true
		}
	}
}
# Start the Session hosts in Peak hours - DepthFirst
function PeakHours-StartSessionHosts-DF
{
	param(
		[string]$TenantName,
		[string]$HostpoolName,
		[int]$SessionhostLimit,
		[int]$HostpoolMaxSessionLimit,
		[int]$MinimumNumberOfRDSH
	)

	# Check the number of running session hosts
	$NumberOfRunningHost = 0
	foreach ($SessionHost in $AllSessionHosts) {

		Write-Output "Checking session host:$($SessionHost.SessionHostName | Out-String)  of sessions:$($SessionHost.Sessions) and status:$($SessionHost.Status)"
		$SessionCapacityofSessionHost = $SessionHost.Sessions
		# Check the Session host is in maintenance
		Check-IfSessionHostInMaintenance -VMName $VMName
		if ($SessionHostLimit -lt $SessionCapacityofSessionHost -or $SessionHost.Status -eq "Available") {
			$NumberOfRunningHost = $NumberOfRunningHost + 1
		}
	}
	Write-Output "Current number of running hosts: $NumberOfRunningHost"
	if ($NumberOfRunningHost -lt $MinimumNumberOfRDSH)
	{
		Write-Output "Current number of running session hosts is less than minimum requirements, start session host ..."
		foreach ($SessionHost in $AllSessionHosts) {

			if ($NumberOfRunningHost -lt $MinimumNumberOfRDSH) {
				$SessionHostSessions = $SessionHost.Sessions
				if ($HostpoolMaxSessionLimit -ne $SessionHostSessions) {
					# Check the session host status and if the session host is healthy before starting the host
					if ($SessionHost.Status -eq "NoHeartbeat" -and $SessionHost.UpdateState -eq "Succeeded") {
						$SessionHostName = $SessionHost.SessionHostName | Out-String
						$VMName = $SessionHostName.Split(".")[0]
						# Check if the session host is in maintenance
						Check-IfSessionHostInMaintenance -VMName $VMName
						# Check if the session host is Allowing NewConnections
						Check-ForAllowNewConnections -TenantName $TenantName -HostPoolName $HostPoolName -SessionHostName $SessionHost.SessionHostName
						# Start the Az VM
						Start-SessionHost -VMName $VMName
						# Wait for the sessionhost is available
						Check-IfSessionHostIsAvailable -TenantName $TenantName -HostPoolName $HostpoolName -SessionHost $SessionHost.SessionHostName
					}
				}
				# Increment the number of running session host
				$NumberOfRunningHost = $NumberOfRunningHost + 1
			}

		}
	}
	else {
		foreach ($SessionHost in $AllSessionHosts) {
			if ($SessionHost.Sessions -ne $HostpoolMaxSessionLimit) {
				if ($SessionHost.Sessions -ge $SessionHostLimit) {
					foreach ($SessionHost in $AllSessionHosts) {

						# Check the session host status and if the session host is healthy before starting the host
						if ($SessionHost.UpdateState -eq "Succeeded") {
							Write-Output "Existing Sessionhost Sessions value reached near by hostpool maximumsession limit need to start the session host"
							$SessionHostName = $SessionHost.SessionHostName | Out-String
							$VMName = $SessionHostName.Split(".")[0]

							# Check the session host is in maintenance
							Check-IfSessionHostInMaintenance -VMName $VMName

							# Validating session host is allowing new connections
							Check-ForAllowNewConnections -TenantName $TenantName -HostPoolName $HostPoolName -SessionHostName $SessionHost.SessionHostName

							# Start the Az VM
							Start-SessionHost -VMName $VNName

							# Wait for the sessionhost is available
							Check-IfSessionHostIsAvailable -TenantName $TenantName -HostPoolName $HostpoolName -SessionHost $SessionHost.SessionHostName
							# Increment the number of running session host
							$NumberOfRunningHost = $NumberOfRunningHost + 1
							break
						}
					}

				}
			}
		}
	}
	Write-Output "HostpoolName:$HostpoolName, NumberofRunnighosts:$NumberOfRunningHost"
}
# Start the session hosts in Peak hours - BreadthFirst
function PeakHours-StartSessionHosts-BF
{
	param(
		[string]$TenantName,
		[string]$HostpoolName,
		[int]$MinimumNoOfRDSH,
		[int]$SessionThresholdPerCPU,
		[int]$TotalRunningCores,
		[int]$NumberOfRunningHost,
		[int]$AvailableSessionCapacity
	)
	# Check the number of running session hosts
	$NumberOfRunningHost = 0
	# Total of running cores
	$TotalRunningCores = 0
	# Total capacity of sessions of running VMs
	$AvailableSessionCapacity = 0
	foreach ($SessionHost in $AllSessionHosts) {
		Write-Output "Checking session host:$($SessionHost.SessionHostName | Out-String)  of sessions:$($SessionHost.Sessions) and status:$($SessionHost.Status)"
		$SessionHostName = $SessionHost.SessionHostName | Out-String
		$VMName = $SessionHostName.Split(".")[0]

		# Check the Session host is in maintenance
		Check-IfSessionHostInMaintenance -VMName $VMName

		$RoleInstance = Get-AzVM -Status | Where-Object { $_.Name.Contains($VMName) }
		if ($SessionHostName.ToLower().Contains($RoleInstance.Name.ToLower())) {
			# Check if the Azure vm is running       
			if ($RoleInstance.PowerState -eq "VM running") {
				$NumberOfRunningHost = $NumberOfRunningHost + 1
				# Calculate available capacity of sessions						
				$RoleSize = Get-AzVMSize -Location $RoleInstance.Location | Where-Object { $_.Name -eq $RoleInstance.HardwareProfile.VmSize }
				$AvailableSessionCapacity = $AvailableSessionCapacity + $RoleSize.NumberOfCores * $SessionThresholdPerCPU
				$TotalRunningCores = $TotalRunningCores + $RoleSize.NumberOfCores
			}

		}

	}
	Write-Output "Current number of running hosts:$NumberOfRunningHost"
	if ($NumberOfRunningHost -lt $MinimumNumberOfRDSH) {

		Write-Output "Current number of running session hosts is less than minimum requirements, start session host ..."
		# Start VM to meet the minimum requirement            
		foreach ($SessionHost in $AllSessionHosts.SessionHostName) {

			# Check whether the number of running VMs meets the minimum or not
			if ($NumberOfRunningHost -lt $MinimumNumberOfRDSH) {

				$VMName = $SessionHost.Split(".")[0]

				# Check if the Session host is in maintenance
				Check-IfSessionHostInMaintenance -VMName $VMName

				$RoleInstance = Get-AzVM -Status | Where-Object { $_.Name.Contains($VMName) }

				if ($SessionHost.ToLower().Contains($RoleInstance.Name.ToLower())) {

					# Check if the Azure VM is running and if the session host is healthy
					$SessionHostInfo = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost
					if ($RoleInstance.PowerState -ne "VM running" -and $SessionHostInfo.UpdateState -eq "Succeeded") {
						# Check if the session host is allowing new connections
						# Validating session host is allowing new connections
						Check-ForAllowNewConnections -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $SessionHost
						# Start the Az VM
						Start-SessionHost -VMName $VMName
						# Wait for the VM to start
						Check-IfSessionHostIsAvailable -TenantName $TenantName -HostPoolName $HostpoolName -SessionHost $SessionHost
						# Calculate available capacity of sessions
						$RoleSize = Get-AzVMSize -Location $RoleInstance.Location | Where-Object { $_.Name -eq $RoleInstance.HardwareProfile.VmSize }
						$AvailableSessionCapacity = $AvailableSessionCapacity + $RoleSize.NumberOfCores * $SessionThresholdPerCPU
						$NumberOfRunningHost = $NumberOfRunningHost + 1
						$TotalRunningCores = $TotalRunningCores + $RoleSize.NumberOfCores
						if ($NumberOfRunningHost -ge $MinimumNumberOfRDSH) {
							break;
						}
					}
				}
			}
		}
	}
	else {
		#check if the available capacity meets the number of sessions or not
		Write-Output "Current total number of user sessions: $(($HostPoolUserSessions).Count)"
		Write-Output "Current available session capacity is: $AvailableSessionCapacity"
		if ($HostPoolUserSessions.Count -ge $AvailableSessionCapacity) {
			Write-Output "Current available session capacity is less than demanded user sessions, starting session host"
			# Running out of capacity, we need to start more VMs if there are any 
			foreach ($SessionHost in $AllSessionHosts.SessionHostName) {
				if ($HostPoolUserSessions.Count -ge $AvailableSessionCapacity) {
					$VMName = $SessionHost.Split(".")[0]
					# Check the Session host is in maintenance
					Check-IfSessionHostInMaintenance -VMName $VMName

					$RoleInstance = Get-AzVM -Status | Where-Object { $_.Name.Contains($VMName) }

					if ($SessionHost.ToLower().Contains($RoleInstance.Name.ToLower())) {
						# Check if the Azure VM is running and if the session host is healthy
						$SessionHostInfo = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost
						if ($RoleInstance.PowerState -ne "VM running" -and $SessionHostInfo.UpdateState -eq "Succeeded") {
							# Validating session host is allowing new connections
							Check-ForAllowNewConnections -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $SessionHost
							# Start the Az VM
							Start-SessionHost -VMName $VMName
							# Wait for the VM to Start
							Check-IfSessionHostIsAvailable -TenantName $TenantName -HostPoolName $HostpoolName -SessionHost $SessionHost
							# Calculate available capacity of sessions
							$RoleSize = Get-AzVMSize -Location $RoleInstance.Location | Where-Object { $_.Name -eq $RoleInstance.HardwareProfile.VmSize }
							$AvailableSessionCapacity = $AvailableSessionCapacity + $RoleSize.NumberOfCores * $SessionThresholdPerCPU
							$NumberOfRunningHost = $NumberOfRunningHost + 1
							$TotalRunningCores = $TotalRunningCores + $RoleSize.NumberOfCores
							Write-Output "New available session capacity is: $AvailableSessionCapacity"
							if ($AvailableSessionCapacity -gt $HostPoolUserSessions.Count) {
								break
							}
						}
						#Break # break out of the inner foreach loop once a match is found and checked
					}
				}
			}
		}
	}
	Write-Output "HostpoolName:$HostpoolName, TotalRunningCores:$TotalRunningCores NumberOfRunningHost:$NumberOfRunningHost"

}
# Log off User Sessions in Off peak hours
function SignOfUserSessions
{
	param(
		[string]$TenantName,
		[string]$HostpoolName,
		[string]$SessionHostName,
		[int]$LimitSecondsToForceLogOffUser,
		[string]$LogOffMessageTitle,
		[string]$LogOffMessageBody
	)
	# Ensure the running Azure VM is set as drain mode
	try {
		Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost -AllowNewSession $false -ErrorAction SilentlyContinue
	}
	catch {
		Write-Output "Unable to set it to allow connections on session host: $($SessionHost.SessionHost) with error: $($_.exception.message)"
		exit 1
	}
	# Notify user to log off session
	# Get the user sessions in the hostPool
	try {
		$HostPoolUserSessions = Get-RdsUserSession -TenantName $TenantName -HostPoolName $HostpoolName
	}
	catch {
		Write-Output "Failed to retrieve user sessions in hostPool: $($HostpoolName) with error: $($_.exception.message)"
		exit 1
	}
	$HostUserSessionCount = ($HostPoolUserSessions | Where-Object -FilterScript { $_.SessionHostName -eq $SessionHost }).Count
	Write-Output "Counting the current sessions on the host $SessionHost...:$HostUserSessionCount"
	$ExistingSession = 0
	foreach ($session in $HostPoolUserSessions) {
		if ($session.SessionHostName -eq $SessionHost) {
			if ($LimitSecondsToForceLogOffUser -ne 0) {
				# Send notification
				try {
					Send-RdsUserSessionMessage -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $SessionHost -SessionId $session.sessionid -MessageTitle $LogOffMessageTitle -MessageBody "$($LogOffMessageBody) You will logged off in $($LimitSecondsToForceLogOffUser) seconds." -NoUserPrompt
				}
				catch {
					Write-Output "Failed to send message to user with error: $($_.exception.message)"
					exit 1
				}
			}
			$ExistingSession = $ExistingSession + 1
		}
	}
	# Wait for n seconds to log off user
	Start-Sleep -Seconds $LimitSecondsToForceLogOffUser
	if ($LimitSecondsToForceLogOffUser -ne 0) {
		# Force users to log off
		Write-Output "Force users to log off..."
		try {
			$HostPoolUserSessions = Get-RdsUserSession -TenantName $TenantName -HostPoolName $HostpoolName
		}
		catch {
			Write-Output "Failed to retrieve list of user sessions in hostPool: $($HostpoolName) with error: $($_.exception.message)"
			exit 1
		}
		foreach ($Session in $HostPoolUserSessions) {
			if ($Session.SessionHostName -eq $SessionHost) {
				#Log off user
				try {
					Invoke-RdsUserSessionLogoff -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $Session.SessionHostName -SessionId $Session.sessionid -NoUserPrompt
					$ExistingSession = $ExistingSession - 1
				}
				catch {
					Write-Output "Failed to log off user with error: $($_.exception.message)"
					exit 1
				}
			}
		}
	}
	return $ExistingSession
}
# Shutdown session hosts in Off peak hours
function OffPeakSessionHost-Shutdown
{
	param(
		[string]$Type,
		[int]$MinimumNumberOfRDSH,
		[int]$NumberOfRunningHost,
		[int]$TotalRunningCores,
		[string]$TenantName,
		[string]$HostpoolName,
		[int]$LimitSecondsToForceLogOffUser,
		[string]$LogOffMessageTitle,
		[string]$LogOffMessageBody
	)

	# Collect the all session hosts of hostpool
	$UserSessionsOfHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName | Sort-Object Sessions
	if ($Type -eq "DepthFirst")
	{
		#Depth First session hosts shutdown in off peak hours.
		if ($NumberOfRunningHost -gt $MinimumNumberOfRDSH) {
			foreach ($SessionHost in $UserSessionsOfHosts) {
				if ($SessionHost.Status -ne "NoHeartbeat") {
					if ($NumberOfRunningHost -gt $MinimumNumberOfRDSH) {
						$SessionHostName = $SessionHost.SessionHostName
						$VMName = $SessionHostName.Split(".")[0]
						if ($SessionHost.Sessions -eq 0)
						{
							# Check the Session host is in maintenance, which session have 0 sessions
							Check-IfSessionHostInMaintenance -VMName $VMName
							# Shutdown the Azure VM, which session host have 0 sessions
							Stop-SessionHost -VMName $VMName
						}
						else
						{
							# Sign of the user sessions which are active in each sesssion host
							$UserSessionsOfHost = SignOfUserSessions -TenantName $TenantName -HostPoolName $HostPoolName -SessionHost $SessionHostName -LimitSecondsToForceLogOffUser $LimitSecondsToForceLogOffUser -LogOffMessageTitle $LogOffMessageTitle -LogOffMessageBody $LogOffMessageBody
							# Check the Session host is in maintenance
							Check-IfSessionHostInMaintenance -VMName $VMName
							# Check the session count before shutting down the VM
							if ($UserSessionsOfHost -eq 0) {
								# Shutdown the Azure VM
								Stop-SessionHost -VMName $VMName
							}
						}
						$SessionHostInfo = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHostName
						# Check if the session host server is healthy before enable allowing new connections
						if ($SessionHostInfo.UpdateState -eq "Succeeded" -and $SessionHostInfo.AllowNewSession -eq $false) {
							# Ensure Azure VMs that are stopped have the allowing new connections state True
							Check-ForAllowNewConnections -TenantName $TenantName -HostPoolName $HostPoolName -SessionHostName $SessionHostName
						}
						# Decrement the number of running session host
						$NumberOfRunningHost = $NumberOfRunningHost - 1
					}
				}
			}
		}
		return $NumberofRunnighost
		Write-Output "HostpoolName:$HostpoolName, NumberofRunnighosts:$NumberOfRunningHost"
	}
	else
	{
		# Breadth frist session hosts shutdown in off peak hours
		if ($NumberOfRunningHost -gt $MinimumNumberOfRDSH) {
			foreach ($SessionHost in $UserSessionsOfHosts) {
				#Check the status of the session host
				if ($SessionHost.Status -ne "NoHeartbeat") {
					if ($NumberOfRunningHost -gt $MinimumNumberOfRDSH) {
						$SessionHostName = $SessionHost.SessionHostName
						$VMName = $SessionHostName.Split(".")[0]
						if ($SessionHost.Sessions -eq 0) {
							# Check the Session host is in maintenance, which session have 0 sessions
							Check-IfSessionHostInMaintenance -VMName $VMName
							# Shutdown the Azure VM, which session host have 0 sessions
							Stop-SessionHost -VMName $VMName
						}
						else {
							# Sign of the user sessions which are active in each sesssion host
							$UserSessionsOfHost = SignOfUserSessions -TenantName $TenantName -HostPoolName $HostPoolName -SessionHost $SessionHostName -LimitSecondsToForceLogOffUser $LimitSecondsToForceLogOffUser -LogOffMessageTitle $LogOffMessageTitle -LogOffMessageBody $LogOffMessageBody
							# Check the session count before shutting down the VM
							if ($UserSessionsOfHost -eq 0) {
								# Check the Session host is in maintenance
								Check-IfSessionHostInMaintenance -VMName $VMName
								# Shutdown the Azure VM
								Stop-SessionHost -VMName $VMName
							}
						}
						#wait for the VM to stop
						$IsVMStopped = $false
						while (!$IsVMStopped) {
							$RoleInstance = Get-AzVM -Status | Where-Object { $_.Name -eq $VMName }
							if ($RoleInstance.PowerState -eq "VM deallocated") {
								$IsVMStopped = $true
								Write-Output "Azure VM has been stopped: $($RoleInstance.Name) ..."
							}
							else {
								Write-Output "Waiting for Azure VM to stop $($RoleInstance.Name) ..."
							}
						}
						$SessionHostInfo = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHostName
						if ($SessionHostInfo.UpdateState -eq "Succeeded" -and $SessionHostInfo.AllowNewSession -eq $false) {
							# Ensure the Azure VMs that are off have Allow new connections mode set to True
							Check-ForAllowNewConnections -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $SessionHostName
						}
						$RoleSize = Get-AzVMSize -Location $RoleInstance.Location | Where-Object { $_.Name -eq $RoleInstance.HardwareProfile.VmSize }
						#decrement number of running session host
						$NumberOfRunningHost = $NumberOfRunningHost - 1
						$TotalRunningCores = $TotalRunningCores - $RoleSize.NumberOfCores
					}
				}
			}
		}
		return $NumberofRunnigHost,$TotalRunningCores
		Write-Output "HostpoolName:$HostpoolName, TotalRunningCores:$TotalRunningCores NumberOfRunningHost:$NumberOfRunningHost"
	}
}
# Check the Off peak time UserSession usage and spin up the Session Host
function OffPeakUserSessionUsage-SpinUpSessionHost
{
	param(
		[string]$NumberOfRunningHost,
		[string]$MinimumNumberOfRDSH,
		[string]$TotalRunningCores,
		[string]$DefinedMinimumNumberOfRDSH,
		[string]$TenantName,
		[string]$HostpoolName,
		[string]$Type
	)
	$AllSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName
	$AutomationAccount = Get-AzAutomationAccount -ErrorAction SilentlyContinue | Where-Object { $_.AutomationAccountName -eq $AutomationAccountName }
	$OffPeakUsageMinimumNoOfRDSH = Get-AzAutomationVariable -Name "OffPeakUsage-MinimumNoOfRDSH" -ResourceGroupName $AutomationAccount.ResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName -ErrorAction SilentlyContinue
	if ($OffPeakUsageMinimumNoOfRDSH) {
		[int]$MinimumNumberOfRDSH = $OffPeakUsageMinimumNoOfRDSH.Value
		$NoConnectionsofhost = 0
		if ($NumberOfRunningHost -le $MinimumNumberOfRDSH) {
			foreach ($SessionHost in $AllSessionHosts) {
				if ($SessionHost.Status -eq "Available" -and $SessionHost.Sessions -eq 0) {
					$NoConnectionsofhost = $NoConnectionsofhost + 1
				}
			}
			if ($NoConnectionsofhost -gt $DefinedMinimumNumberOfRDSH) {
				[int]$MinimumNumberOfRDSH = [int]$MinimumNumberOfRDSH - $NoConnectionsofhost
				Set-AzAutomationVariable -Name "OffPeakUsage-MinimumNoOfRDSH" -ResourceGroupName $AutomationAccount.ResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName -Encrypted $false -Value $MinimumNumberOfRDSH
			}
		}
	}
	$HostpoolMaxSessionLimit = $HostpoolInfo.MaxSessionLimit
	$HostpoolSessionCount = (Get-RdsUserSession -TenantName $TenantName -HostPoolName $HostpoolName).Count
	if ($HostpoolSessionCount -eq 0) {
		Write-Output "HostpoolName:$HostpoolName, NumberofRunnighosts:$NumberOfRunningHost"
		break
	}
	else {
		# Calculate the how many sessions will allow in minimum number of RDSH VMs in off peak hours and calculate TotalAllowSessions Scale Factor
		$TotalAllowSessionsInOffPeak = [int]$MinimumNumberOfRDSH * $HostpoolMaxSessionLimit
		$SessionsScaleFactor = $TotalAllowSessionsInOffPeak * 0.90
		$ScaleFactor = [math]::Floor($SessionsScaleFactor)

		if ($HostpoolSessionCount -ge $ScaleFactor) {
			foreach ($SessionHost in $AllSessionHosts) {
				if ($SessionHost.Sessions -ge $SessionHostLimit) {
					$AllSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName | Sort-Object Sessions | Sort-Object Status
					foreach ($SessionHost in $AllSessionHosts) {
						if ($SessionHost.Status -eq "Available" -and $SessionHost.Sessions -eq 0)
						{ break }
						# Check the session host status and if the session host is healthy before starting the host
						if ($SessionHost.Status -eq "NoHeartbeat" -and $SessionHost.UpdateState -eq "Succeeded") {
							Write-Output "Existing Sessionhost Sessions value reached near by hostpool maximumsession limit need to start the session host"
							$SessionHostName = $SessionHost.SessionHostName | Out-String
							$VMName = $SessionHostName.Split(".")[0]
							# Check the Session host is in maintenance
							Check-IfSessionHostInMaintenance -VMName $VMName
							# Validating session host is allowing new connections
							Check-ForAllowNewConnections -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $SessionHost.SessionHostName
							# Start the Az VM
							Start-SessionHost -VMName $VMName
							# Wait for the sessionhost is available
							Check-IfSessionHostIsAvailable -TenantName $TenantName -HostPoolName $HostpoolName -SessionHost $SessionHost.SessionHostName
							# Increment the number of running session host
							$NumberOfRunningHost = $NumberOfRunningHost + 1
							# Increment the number of minimumnumberofrdsh
							[int]$MinimumNumberOfRDSH = [int]$MinimumNumberOfRDSH + 1
							$OffPeakUsageMinimumNoOfRDSH = Get-AzAutomationVariable -Name "OffPeakUsage-MinimumNoOfRDSH" -ResourceGroupName $AutomationAccount.ResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName -ErrorAction SilentlyContinue
							if ($OffPeakUsageMinimumNoOfRDSH -eq $null) {
								New-AzAutomationVariable -Name "OffPeakUsage-MinimumNoOfRDSH" -ResourceGroupName $AutomationAccount.ResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName -Encrypted $false -Value $MinimumNumberOfRDSH -Description "Dynamically generated minimumnumber of RDSH value"
							}
							else {
								Set-AzAutomationVariable -Name "OffPeakUsage-MinimumNoOfRDSH" -ResourceGroupName $AutomationAccount.ResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName -Encrypted $false -Value $MinimumNumberOfRDSH
							}
							if ($type -eq "DepthFirst") {
								Write-Output "HostpoolName:$HostpoolName, NumberofRunnighosts:$NumberOfRunningHost"
							} else {
								# Calculate available capacity of sessions
								$RoleSize = Get-AzVMSize -Location $RoleInstance.Location | Where-Object { $_.Name -eq $RoleInstance.HardwareProfile.VmSize }
								$AvailableSessionCapacity = $TotalAllowSessions + $HostpoolInfo.MaxSessionLimit
								$TotalRunningCores = $TotalRunningCores + $RoleSize.NumberOfCores
								Write-Output "New available session capacity is: $AvailableSessionCapacity"
								Write-Output "HostpoolName:$HostpoolName, TotalRunningCores:$TotalRunningCores NumberOfRunningHost:$NumberOfRunningHost"
							}
							break
						}
					}

				}
			}
		}
	}
}

#Converting date time from UTC to Local
$CurrentDateTime = Convert-UTCtoLocalTime -TimeDifferenceInHours $TimeDifference

#Set context to the appropriate tenant group
$CurrentTenantGroupName = (Get-RdsContext).TenantGroupName
if ($TenantGroupName -ne $CurrentTenantGroupName) {
	Write-Output "Running switching to the $TenantGroupName context"
	Set-RdsContext -TenantGroupName $TenantGroupName
}

$BeginPeakDateTime = [datetime]::Parse($CurrentDateTime.ToShortDateString() + ' ' + $BeginPeakTime)
$EndPeakDateTime = [datetime]::Parse($CurrentDateTime.ToShortDateString() + ' ' + $EndPeakTime)

#check the calculated end time is later than begin time in case of time zone
if ($EndPeakDateTime -lt $BeginPeakDateTime) {
	$EndPeakDateTime = $EndPeakDateTime.AddDays(1)
}

#Checking givne host pool name exists in Tenant
$HostpoolInfo = Get-RdsHostPool -TenantName $TenantName -Name $HostpoolName
if ($HostpoolInfo -eq $null) {
	Write-Output "Hostpoolname '$HostpoolName' does not exist in the tenant of '$TenantName'. Ensure that you have entered the correct values."
	exit
}

# Setting up appropriate load balacing type based on PeakLoadBalancingType in Peak hours
$HostpoolLoadbalancerType = $HostpoolInfo.LoadBalancerType
[int]$MaxSessionLimitValue = $HostpoolInfo.MaxSessionLimit
if ($CurrentDateTime -ge $BeginPeakDateTime -and $CurrentDateTime -le $EndPeakDateTime) {
	Updating-LoadBalancingTypeInPeakHours -HostpoolLoadbalancerType $HostpoolLoadbalancerType -PeakLoadBalancingType $PeakLoadBalancingType -TenantName $TenantName -HostPoolName $HostpoolName -MaxSessionLimitValue $MaxSessionLimitValue
}
else {
	Updating-LoadBalancingTypeINOffPeakHours -HostpoolLoadbalancerType $HostpoolLoadbalancerType -PeakLoadBalancingType $PeakloadbalancingType -TenantName $TenantName -HostPoolName $HostpoolName -MaxSessionLimitValue $MaxSessionLimitValue
}
Write-Output "Starting WVD Tenant Hosts Scale Optimization: Current Date Time is: $CurrentDateTime"
# Check the after changing hostpool loadbalancer type
$HostpoolInfo = Get-RdsHostPool -TenantName $TenantName -Name $HostPoolName

# Check if the hostpool have session hosts
$AllSessionHosts = Check-IfHostpoolHaveSessionHosts -TenantName $TenantName -HostPoolName $HostpoolName
if ($HostpoolInfo.LoadBalancerType -eq "DepthFirst")
{
	Write-Output "$HostpoolName hostpool loadbalancer type is $($HostpoolInfo.LoadBalancerType)"
	#Gathering hostpool maximum session and calculating Scalefactor for each host.										  
	$HostpoolMaxSessionLimit = $HostpoolInfo.MaxSessionLimit
	$ScaleFactorEachHost = $HostpoolMaxSessionLimit * 0.80
	$SessionhostLimit = [math]::Floor($ScaleFactorEachHost)
	Write-Output "Hostpool Maximum Session Limit: $($HostpoolMaxSessionLimit)"
	if ($CurrentDateTime -ge $BeginPeakDateTime -and $CurrentDateTime -le $EndPeakDateTime)
	{
		Write-Output "It is in peak hours now"
		Write-Output "Peak hours: starting session hosts as needed based on current workloads."

		# Peak hours check and remove the MinimumnoofRDSH value dynamically stored in automation variable 												   
		$AutomationAccount = Get-AzAutomationAccount -ErrorAction SilentlyContinue | Where-Object { $_.AutomationAccountName -eq $AutomationAccountName }
		$OffPeakUsageMinimumNoOfRDSH = Get-AzAutomationVariable -Name "OffPeakUsage-MinimumNoOfRDSH" -ResourceGroupName $AutomationAccount.ResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName -ErrorAction SilentlyContinue
		if ($OffPeakUsageMinimumNoOfRDSH) {
			Remove-AzAutomationVariable -Name "OffPeakUsage-MinimumNoOfRDSH" -ResourceGroupName $AutomationAccount.ResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName
		}
		###############Peak hours start the Session Hosts#########
		PeakHours-StartSessionHosts-DF -TenantName $TenantName -HostPoolName $HostpoolName -SessionhostLimit $SessionhostLimit -HostpoolMaxSessionLimit $HostpoolMaxSessionLimit -MinimumNoOfRDSH $MinimumNoOfRDSH
	}
	else {
		Write-Output "It is Off-peak hours"
		Write-Output "It is off-peak hours. Starting to scale down RD session hosts..."
		#Check the number running session hosts of hostpool
		$NumberOfRunningHost = 0
		foreach ($SessionHost in $AllSessionHosts) {
			if ($SessionHost.Status -eq "Available") {
				Write-Output "Checking session host:$($SessionHost.SessionHostName | Out-String)  of sessions:$($SessionHost.Sessions) and status:$($SessionHost.Status)"
				$NumberOfRunningHost = $NumberOfRunningHost + 1
			}
		}
		# Defined minimum no of rdsh value from JSON file
		[int]$DefinedMinimumNumberOfRDSH = $MinimumNumberOfRDSH

		# Check and Collecting dynamically stored MinimumNoOfRDSH Value																 
		$AutomationAccount = Get-AzAutomationAccount -ErrorAction SilentlyContinue | Where-Object { $_.AutomationAccountName -eq $AutomationAccountName }
		$OffPeakUsageMinimumNoOfRDSH = Get-AzAutomationVariable -Name "OffPeakUsage-MinimumNoOfRDSH" -ResourceGroupName $AutomationAccount.ResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName -ErrorAction SilentlyContinue
		if ($OffPeakUsageMinimumNoOfRDSH) {
			[int]$MinimumNumberOfRDSH = $OffPeakUsageMinimumNoOfRDSH.Value
		}

		########Shut down the session hosts in Off peak hours###############
		OffPeakSessionHost-Shutdown -Type "DepthFirst" -TenantName $TenantName -HostPoolName $HostpoolName -LimitSecondsToForceLogOffUser $LimitSecondsToForceLogOffUser -LogOffMessageTitle $LogOffMessageTitle -LogOffMessageBody $LogOffMessageBody -NumberOfRunningHost $NumberOfRunningHost -MinimumNumberOfRDSH $MinimumNumberOfRDSH
		# Check the Off peak User Sessions Usage and Spin up the Session host
		OffPeakUserSessionUsage-SpinUpSessionHost -NumberOfRunningHost $NumberOfRunningHost -MinimumNumberOfRDSH $MinimumNumberOfRDSH -DefinedMinimumNumberOfRDSH $DefinedMinimumNumberOfRDSH -TenantName $TenantName -HostPoolName $HostpoolName -Type "DepthFirst"

	}
	Write-Output "End WVD Tenant Scale Optimization."
}
else {
	Write-Output "$HostpoolName hostpool loadbalancer type is $($HostpoolInfo.LoadBalancerType)"
	# Check if it is during the peak or off-peak time
	if ($CurrentDateTime -ge $BeginPeakDateTime -and $CurrentDateTime -le $EndPeakDateTime)
	{
		Write-Output "It is in peak hours now"
		Write-Output "Peak hours: starting session hosts as needed based on current workloads."

		# Peak hours check and remove the MinimumnoofRDSH value dynamically stored in automation variable 												   
		$AutomationAccount = Get-AzAutomationAccount -ErrorAction SilentlyContinue | Where-Object { $_.AutomationAccountName -eq $AutomationAccountName }
		$OffPeakUsageMinimumNoOfRDSH = Get-AzAutomationVariable -Name "OffPeakUsage-MinimumNoOfRDSH" -ResourceGroupName $AutomationAccount.ResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName -ErrorAction SilentlyContinue
		if ($OffPeakUsageMinimumNoOfRDSH) {
			Remove-AzAutomationVariable -Name "OffPeakUsage-MinimumNoOfRDSH" -ResourceGroupName $AutomationAccount.ResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName
		}
		##############Peak Hours starting session hosts######
		PeakHours-StartSessionHosts-BF -TenantName $TenantName -HostPoolName $HostpoolName -MinimumNoOfRDSH $MinimumNoOfRDSH -SessionThresholdPerCPU $SessionThresholdPerCPU
	}
	else
	{
		Write-Output "It is Off-peak hours"
		Write-Output "It is off-peak hours. Starting to scale down RD session hosts..."
		Write-Output "Processing hostPool $($HostpoolName)"
		# Check the number of running session hosts
		$NumberOfRunningHost = 0
		# Total number of running cores
		$TotalRunningCores = 0
		foreach ($SessionHost in $AllSessionHosts) {
			$SessionHostName = $SessionHost.SessionHostName
			Write-Output "Checking session host:$($SessionHost.SessionHostName | Out-String)  of sessions:$($SessionHost.Sessions) and status:$($SessionHost.Status)"
			$VMName = $SessionHostName.Split(".")[0]
			$RoleInstance = Get-AzVM -Status | Where-Object { $_.Name.Contains($VMName) }
			if ($SessionHostName.ToLower().Contains($RoleInstance.Name.ToLower())) {
				#check if the Azure VM is running or not
				if ($RoleInstance.PowerState -eq "VM running") {
					$NumberOfRunningHost = $NumberOfRunningHost + 1
					# Calculate available capacity of sessions  
					$RoleSize = Get-AzVMSize -Location $RoleInstance.Location | Where-Object { $_.Name -eq $RoleInstance.HardwareProfile.VmSize }
					$TotalRunningCores = $TotalRunningCores + $RoleSize.NumberOfCores
				}
			}
		}
		# Defined minimum no of rdsh value from JSON file
		[int]$DefinedMinimumNumberOfRDSH = $MinimumNumberOfRDSH
		## Check and Collecting dynamically stored MinimumNoOfRDSH Value																 
		$AutomationAccount = Get-AzAutomationAccount -ErrorAction SilentlyContinue | Where-Object { $_.AutomationAccountName -eq $AutomationAccountName }
		$OffPeakUsageMinimumNoOfRDSH = Get-AzAutomationVariable -Name "OffPeakUsage-MinimumNoOfRDSH" -ResourceGroupName $AutomationAccount.ResourceGroupName -AutomationAccountName $AutomationAccount.AutomationAccountName -ErrorAction SilentlyContinue
		if ($OffPeakUsageMinimumNoOfRDSH) {
			[int]$MinimumNumberOfRDSH = $OffPeakUsageMinimumNoOfRDSH.Value
		}
		##############Shut down the session hosts in Off peak hours#############
		OffPeakSessionHost-Shutdown -Type "BreadthFirst" -TenantName $TenantName -HostPoolName $HostpoolName -MinimumNumberOfRDSH $MinimumNumberOfRDSH -NumberOfRunningHost $NumberOfRunningHost -LimitSecondsToForceLogOffUser $LimitSecondsToForceLogOffUser -LogOffMessageTitle $LogOffMessageTitle -LogOffMessageBody $LogOffMessageBody -TotalRunningCores $TotalRunningCores
		# Check the User Sessions Usage in off peak hours and Spin up the Session host
		OffPeakUserSessionUsage-SpinUpSessionHost -NumberOfRunningHost $NumberOfRunningHost -MinimumNumberOfRDSH $MinimumNumberOfRDSH -DefinedMinimumNumberOfRDSH $DefinedMinimumNumberOfRDSH -TenantName $TenantName -HostPoolName $HostpoolName -Type "BreadthFirst"
	}
	Write-Output "End WVD Tenant Scale Optimization."
}