<#	
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.209
	 Created on:   	8/31/2022 6:05 PM
	 Created by:   	lukma
	 Organization: 	Malwatch Security
	 Filename:     	malwatch.psm1
	-------------------------------------------------------------------------
	 Module Name: Malwatch
	===========================================================================
#>


# ############################## #

# NOTE: Before executing a Malwatch command, use "Malwatch-" before the command.

# ############################## #


# ------------------------------
# Function Name: p
# Description: Check if a connection is online.
# Example: p google.com
# Usage: p { host }
# Value: True (Online) // False (Offline)
# ------------------------------

function Malwatch-help
{
	$d = Get-Content('malwatch-commands.json')
	return $d | ConvertFrom-Json
	
}


function Malwatch-p
{
	param ($computername)
	return (Test-Connection $computername -Count 1 -Quiet)
}


# ------------------------------
# Function Name: Get-LoggedIn
# Description: Check if guest or host is logged in.
# Example: Get-LoggedIn localhost
# Usage: Get-LoggedIn { host }
# Value: Computer Name
# ------------------------------

function Malwatch-Get-LoggedIn
{
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $True)]
		[string[]]$computername
	)
	
	foreach ($pc in $computername)
	{
		$logged_in = (Get-WmiObject win32_computersystem -COMPUTER $pc).username
		$name = $logged_in.split("\")[1]
		"{0}: {1}" -f $pc,$name
	}
	
}

# ------------------------------
# Function Name: Get-LocalUptime
# Description: Checks the localhost's uptime.
# Example: Get-LocalUptime
# Usage: Get-LocalUptime
# Value: Days, ComputerName, Hours, Minutes, Seconds
# ------------------------------

function Malwatch-Get-LocalUptime {
	[CmdletBinding()]
	param (
		[string]$ComputerName = 'localhost'
	)
	
	foreach ($Comptuer in $ComputerName)
	{
		$pc = $ComputerName
		$os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName
		$diff = $os.ConvertToDateTime($os.LocalDateTime) - $os.ConvertToDateTime($os.LastBootUpTime)
		
		$properties = @{
			'ComputerName' = $pc;
			'UptimeDays'   = $diff.Days;
			'UptimeHours'   = $diff.Hours;
			'UptimeMinutes'   = $diff.Minutes;
			'UptimeSeconds'   = $diff.Seconds;
		}
		$obj = New-Object -TypeName System.Management.Automation.PSObject -Property $properties
		
		Write-Output $obj
	}
}

# ---------------
# Function Name: Get-HWVersion
# Retreives device name, driver date, and driver version
# ---------------
function Malwatch-Get-HWVersion_DN_DD_DV($computer, $name)
{
	
	$pingresult = Get-WmiObject win32_pingstatus -f "address='$computer'"
	if ($pingresult.statuscode -ne 0) { return }
	
	Get-WmiObject -Query "SELECT * FROM Win32_PnPSignedDriver WHERE DeviceName LIKE '%$name%'" -ComputerName $computer |
	Sort-Object DeviceName |
	Select-Object @{ Name = "Server"; Expression = { $_.__Server } }, DeviceName, @{ Name = "DriverDate"; Expression = { [System.Management.ManagementDateTimeconverter]::ToDateTime($_.DriverDate).ToString("MM/dd/yyyy") } }, DriverVersion
}


function Malwatch-Get-HWVersion($computerName, $name)
{
<# .SYNOPSIS Retreives hardware info .DESCRIPTION Retreives device name, driver date, and driver version .PARAMETER computerName A computer name, or IP address, to query .PARAMETER name full or partial part of a device name .EXAMPLE Get-HWVersion -computerName WIN8 .EXAMPLE Get-HWVersion WIN8 .EXAMPLE Get-HWVersion -name Radeon #>
	Write-Verbose "Verifying the computer is online"
	$pingResult = test-connection $computerName -count 1 -quiet
	if ($pingResult -eq $false)
	{
		Write-Output "$computerName not online"
		return
	}
	
	Write-Verbose "Pulling data from $computerName using WMI"
	gwmi -Query "SELECT * FROM Win32_PnPSignedDriver WHERE DeviceName LIKE '%$name%'" -ComputerName $computerName |
	Sort DeviceName |
	Select @{ Name = "Server"; Expression = { $_.__Server } }, DeviceName, @{ Name = "DriverDate"; Expression = { [System.Management.ManagementDateTimeconverter]::ToDateTime($_.DriverDate).ToString("MM/dd/yyyy") } }, DriverVersion
}

# Export Commands:::

Export-ModuleMember Malwatch-help
Export-ModuleMember Malwatch-p
Export-ModuleMember Malwatch-Get-LoggedIn
Export-ModuleMember Malwatch-Get-LocalUptime
Export-ModuleMember Malwatch-Get-HWVersion_DN_DD_DV
Export-ModuleMember Malwatch-Get-HWVersion





