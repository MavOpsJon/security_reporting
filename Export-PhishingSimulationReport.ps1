<#
.SYNOPSIS
    Export Attack Simulation Training failures with user department and manager information

.DESCRIPTION
    This script retrieves failed users from Microsoft 365 Attack Simulation Training campaigns,
    enriches the data with department and manager information from Microsoft Entra ID,
    and exports to CSV for reporting.

.PARAMETER SimulationId
    Optional. Specific simulation ID to report on. If not provided, gets all recent simulations.

.PARAMETER OutputPath
    Path where the CSV report will be saved. Defaults to current directory.

.PARAMETER DaysBack
    Number of days back to look for simulations. Defaults to 30 days.

.EXAMPLE
    .\Export-PhishingSimulationReport.ps1 -OutputPath "C:\Reports" -DaysBack 90

.NOTES
    Requires:
    - Microsoft.Graph PowerShell SDK (Install-Module Microsoft.Graph)
    - App Registration with permissions:
      - SecurityEvents.Read.All (for simulation data)
      - User.Read.All (for user/department/manager data)
    - Or delegated permissions if running interactively
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$SimulationId,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".",

    [Parameter(Mandatory=$false)]
    [int]$DaysBack = 30
)

# #Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Reports, Microsoft.Graph.Identity.SignIns

# Import required modules
Write-Host "Importing Microsoft Graph modules..." -ForegroundColor Cyan
# Import-Module Microsoft.Graph.Authentication
# Import-Module Microsoft.Graph.Users
# Import-Module Microsoft.Graph.Reports
# Import-Module Microsoft.Graph.Identity.SignIns

# Connect to Microsoft Graph
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Write-Host "Required scopes: AttackSimulation.Read.All, User.Read.All, AuditLog.Read.All" -ForegroundColor Yellow

try {
    Connect-MgGraph -Scopes "AttackSimulation.Read.All", "User.Read.All", "AuditLog.Read.All" -NoWelcome
    Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 1
}

# Initialize results array
$failedUsersReport = @()

# Get simulations
Write-Host "`nRetrieving attack simulation campaigns..." -ForegroundColor Cyan

try {
    if ($SimulationId) {
        # Get specific simulation
        $selectedSimulation = @{
            id = $SimulationId
            displayName = "Provided SimulationId: $SimulationId"
        }
        Write-Host "Using specified simulation ID: $SimulationId" -ForegroundColor Green
    } else {
        # Get all simulations
        $uri = "https://graph.microsoft.com/v1.0/security/attackSimulation/simulations"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET

        # Sort by creation date (most recent first), with fallback for missing dates
        $allSimulations = $response.value | Sort-Object {
            if ($_.createdDateTime) {
                try {
                    $dateStr = $_.createdDateTime

                    # The API returns MM/DD/YYYY format, parse it explicitly using US culture
                    $usCulture = [System.Globalization.CultureInfo]::GetCultureInfo("en-US")
                    $parsedDate = [DateTime]::Parse($dateStr, $usCulture)

                    $parsedDate
                } catch {
                    [DateTime]::MinValue  # Put unparseable dates at the end
                }
            } else {
                [DateTime]::MinValue  # Put missing dates at the end
            }
        } -Descending

        if ($allSimulations.Count -eq 0) {
            Write-Host "No simulations found." -ForegroundColor Yellow
            Disconnect-MgGraph
            exit 0
        }

        # Show interactive selection menu
        Write-Host "`nAvailable Simulations:" -ForegroundColor Cyan
        Write-Host "Select a specific simulation to analyze:" -ForegroundColor Yellow

        for ($i = 0; $i -lt $allSimulations.Count; $i++) {
            $sim = $allSimulations[$i]
            $status = $sim.status

            $dateDisplay = if ($sim.createdDateTime) {
                try {
                    $dateStr = $sim.createdDateTime

                    # The API returns MM/DD/YYYY format, parse it explicitly using US culture
                    $usCulture = [System.Globalization.CultureInfo]::GetCultureInfo("en-US")
                    $parsedDate = [DateTime]::Parse($dateStr, $usCulture)

                    "created on $($parsedDate.ToString("dd/MM/yyyy"))"
                } catch {
                    "created on unknown date"
                }
            } else {
                "created on unknown date"
            }

            Write-Host "$($i + 1). $($sim.displayName) - $dateDisplay (Status: $status)" -ForegroundColor White
        }

        # Hard-coded selection for testing
        $selection = 1
        $selectedSimulation = $allSimulations[$selection - 1]
        Write-Host "Auto-selected: $($selectedSimulation.displayName)" -ForegroundColor Green
    }

} catch {
    Write-Error "Failed to retrieve simulations: $_"
    Disconnect-MgGraph
    exit 1
}

# Get users who failed the selected simulation
$simName = $selectedSimulation.displayName
$simId = $selectedSimulation.id
Write-Host "`nAnalyzing simulation: $simName" -ForegroundColor Cyan
Write-Host "Simulation ID: $simId" -ForegroundColor Gray

try {
    # Try to get simulation participants directly from the simulation endpoint
    Write-Host "`nRetrieving simulation details and participants..." -ForegroundColor Cyan

    try {
        # Try the simulation endpoint to see if it has participant data
        $simUri = "https://graph.microsoft.com/v1.0/security/attackSimulation/simulations/$simId"
        $simulationData = Invoke-MgGraphRequest -Uri $simUri -Method GET

        Write-Host "Simulation details retrieved. Checking for participant data..." -ForegroundColor Gray
        Write-Host "Simulation: $($simulationData.displayName)" -ForegroundColor White
        Write-Host "Status: $($simulationData.status)" -ForegroundColor White

        # Check if the simulation has user data directly
        if ($simulationData.users -or $simulationData.participants -or $simulationData.simulationUsers) {
            Write-Host "Found direct user data in simulation!" -ForegroundColor Green
            # Process direct user data if available
        } else {
            Write-Host "No direct user data in simulation object. Checking for account targets..." -ForegroundColor Yellow

            # Try to get included account targets
            try {
                $includedTargetsUri = "https://graph.microsoft.com/beta/security/attackSimulation/simulations/$simId/includedAccountTarget"
                $includedTargets = Invoke-MgGraphRequest -Uri $includedTargetsUri -Method GET -ErrorAction SilentlyContinue

                if ($includedTargets -and $includedTargets.type) {
                    Write-Host "Found included account targets of type: $($includedTargets.type)" -ForegroundColor Green

                    # If it's addressBook type, there might be user data
                    if ($includedTargets.type -eq "addressBook" -and $includedTargets.accountTargetEmails) {
                        Write-Host "Found target emails in simulation!" -ForegroundColor Green
                        $simulationParticipants = $includedTargets.accountTargetEmails
                        Write-Host "Simulation has $($simulationParticipants.Count) target participants" -ForegroundColor Cyan
                    }
                } else {
                    Write-Host "No usable included account targets found" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Could not retrieve account targets: $_" -ForegroundColor Yellow
            }
        }

    } catch {
        Write-Host "Could not get simulation details: $_" -ForegroundColor Yellow
    }

    # Since direct simulation user data isn't available, we'll use the coverage API
    # but filter the results to show only users and include a note about the limitation
    Write-Host "`nUsing coverage API (limitation: shows all user compromise data)..." -ForegroundColor Cyan
    $coverageUri = "https://graph.microsoft.com/beta/reports/getAttackSimulationSimulationUserCoverage"
    $coverageResponse = Invoke-MgGraphRequest -Uri $coverageUri -Method GET
    $userCoverageData = $coverageResponse.value

    Write-Host "Found $($userCoverageData.Count) total users with simulation data" -ForegroundColor Yellow

    # Filter for users who have been compromised and participated in simulations
    $allCompromisedUsers = $userCoverageData | Where-Object { $_.compromisedCount -gt 0 }
    Write-Host "Found $($allCompromisedUsers.Count) users who have been compromised across ALL simulations" -ForegroundColor Yellow

    # Now filter to only users who were part of the selected simulation
    if ($simulationParticipants -and $simulationParticipants.Count -gt 0) {
        Write-Host "`nFiltering to show only users from the selected simulation..." -ForegroundColor Cyan

        $compromisedUsers = $allCompromisedUsers | Where-Object {
            $userEmail = $_.attackSimulationUser.email
            $simulationParticipants -contains $userEmail
        }

        Write-Host "Found $($compromisedUsers.Count) users who were compromised specifically in '$simName'" -ForegroundColor $(if ($compromisedUsers.Count -gt 0) { "Red" } else { "Green" })
        Write-Host "Out of $($simulationParticipants.Count) total participants in this simulation" -ForegroundColor Gray

        if ($compromisedUsers.Count -eq 0) {
            Write-Host "No users were compromised in the selected simulation '$simName'." -ForegroundColor Green
            Write-Host "This simulation had a 100% success rate!" -ForegroundColor Green
            Disconnect-MgGraph
            exit 0
        }
    } else {
        Write-Host "Could not get simulation participant list - showing all compromised users with limitation note" -ForegroundColor Yellow
        $compromisedUsers = $allCompromisedUsers

        if ($compromisedUsers.Count -eq 0) {
            Write-Host "No failed users found in any simulations." -ForegroundColor Green
            Disconnect-MgGraph
            exit 0
        }
    }

    # Process each compromised user
    foreach ($userCoverage in $compromisedUsers) {
        $userId = $userCoverage.attackSimulationUser.userId
        $userEmail = $userCoverage.attackSimulationUser.email
        $userDisplayName = $userCoverage.attackSimulationUser.displayName
        $latestSimulationDate = $userCoverage.latestSimulationDateTime

        Write-Host "  Processing compromised user: $userDisplayName ($userEmail)" -ForegroundColor Gray

        try {
            # Get detailed user information
            $userUri = "https://graph.microsoft.com/v1.0/users/$($userId)?`$select=displayName,mail,department,jobTitle,officeLocation"
            $userDetails = Invoke-MgGraphRequest -Uri $userUri -Method GET -ErrorAction SilentlyContinue

            # Get manager information
            $managerName = "N/A"
            $managerEmail = "N/A"
            try {
                $managerUri = "https://graph.microsoft.com/v1.0/users/$($userId)/manager?`$select=displayName,mail"
                $managerDetails = Invoke-MgGraphRequest -Uri $managerUri -Method GET -ErrorAction SilentlyContinue
                if ($managerDetails) {
                    $managerName = if ($managerDetails.displayName) { $managerDetails.displayName } else { "N/A" }
                    $managerEmail = if ($managerDetails.mail) { $managerDetails.mail } else { "N/A" }
                }
            } catch {
                Write-Verbose "Could not retrieve manager for $userDisplayName : $_"
            }

            # Get sign-in logs for device information around the compromise time
            $deviceInfo = "N/A"
            $browserInfo = "N/A"
            $osInfo = "N/A"
            $ipAddress = "N/A"

            if ($latestSimulationDate) {
                try {
                    Write-Host "    Checking sign-in logs for device details..." -ForegroundColor DarkGray

                    # Parse the latest simulation time and look for sign-ins within a 2-hour window
                    $simulationTime = [DateTime]::Parse($latestSimulationDate)
                    $startTime = $simulationTime.AddHours(-1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    $endTime = $simulationTime.AddHours(1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

                    # Query sign-in logs
                    $signInUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=userId eq '$userId' and createdDateTime ge $startTime and createdDateTime le $endTime&`$orderby=createdDateTime desc&`$top=5"
                    $signInResponse = Invoke-MgGraphRequest -Uri $signInUri -Method GET -ErrorAction SilentlyContinue

                    if ($signInResponse.value -and $signInResponse.value.Count -gt 0) {
                        # Get the closest sign-in to the simulation time
                        $closestSignIn = $signInResponse.value | Sort-Object {
                            [Math]::Abs(([DateTime]::Parse($_.createdDateTime) - $simulationTime).TotalMinutes)
                        } | Select-Object -First 1

                        if ($closestSignIn.deviceDetail) {
                            $deviceInfo = if ($closestSignIn.deviceDetail.deviceId) {
                                "$($closestSignIn.deviceDetail.displayName) ($($closestSignIn.deviceDetail.operatingSystem))"
                            } else {
                                $closestSignIn.deviceDetail.operatingSystem
                            }
                            $browserInfo = $closestSignIn.deviceDetail.browser
                            $osInfo = $closestSignIn.deviceDetail.operatingSystem
                        }

                        if ($closestSignIn.ipAddress) {
                            $ipAddress = $closestSignIn.ipAddress
                        }

                        if ($closestSignIn.location) {
                            $location = "$($closestSignIn.location.city), $($closestSignIn.location.countryOrRegion)"
                        } else {
                            $location = "N/A"
                        }
                    }
                } catch {
                    Write-Verbose "Could not retrieve sign-in logs for $userDisplayName : $_"
                }
            }

            # Create report object
            $reportObject = [PSCustomObject]@{
                SelectedSimulation = $simName
                SimulationSpecific = if ($simulationParticipants -and $simulationParticipants.Count -gt 0) { "Yes - filtered to this simulation" } else { "No - API limitation, shows all compromised users" }
                UserDisplayName = $userDisplayName
                UserEmail = $userEmail
                UserId = $userId
                Department = if ($userDetails.department) { $userDetails.department } else { "N/A" }
                JobTitle = if ($userDetails.jobTitle) { $userDetails.jobTitle } else { "N/A" }
                OfficeLocation = if ($userDetails.officeLocation) { $userDetails.officeLocation } else { "N/A" }
                ManagerName = $managerName
                ManagerEmail = $managerEmail
                TotalSimulations = $userCoverage.simulationCount
                TotalClicks = $userCoverage.clickCount
                TotalCompromised = $userCoverage.compromisedCount
                CompromiseRate = [math]::Round(($userCoverage.compromisedCount / $userCoverage.simulationCount) * 100, 2)
                LatestSimulationDate = $latestSimulationDate
                DeviceInfo = $deviceInfo
                Browser = $browserInfo
                OperatingSystem = $osInfo
                IPAddress = $ipAddress
                Location = if ($location) { $location } else { "N/A" }
            }

            $failedUsersReport += $reportObject

        } catch {
            Write-Warning "Could not retrieve details for user $userDisplayName : $_"

            # Add minimal record
            $reportObject = [PSCustomObject]@{
                SelectedSimulation = $simName
                SimulationSpecific = if ($simulationParticipants -and $simulationParticipants.Count -gt 0) { "Yes - filtered to this simulation" } else { "No - API limitation, shows all compromised users" }
                UserDisplayName = $userDisplayName
                UserEmail = $userEmail
                UserId = $userId
                Department = "Unable to retrieve"
                JobTitle = "Unable to retrieve"
                OfficeLocation = "Unable to retrieve"
                ManagerName = "Unable to retrieve"
                ManagerEmail = "Unable to retrieve"
                TotalSimulations = $userCoverage.simulationCount
                TotalClicks = $userCoverage.clickCount
                TotalCompromised = $userCoverage.compromisedCount
                CompromiseRate = [math]::Round(($userCoverage.compromisedCount / $userCoverage.simulationCount) * 100, 2)
                LatestSimulationDate = $latestSimulationDate
                DeviceInfo = "Unable to retrieve"
                Browser = "Unable to retrieve"
                OperatingSystem = "Unable to retrieve"
                IPAddress = "Unable to retrieve"
                Location = "Unable to retrieve"
            }

            $failedUsersReport += $reportObject
        }
    }

} catch {
    Write-Error "Failed to retrieve simulation report: $_"
    Disconnect-MgGraph
    exit 1
}

# Export results
if ($failedUsersReport.Count -gt 0) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $outputFile = Join-Path $OutputPath "PhishingSimulation-FailedUsers-$timestamp.csv"

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "EXPORT SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Total failed users: $($failedUsersReport.Count)" -ForegroundColor Yellow
    Write-Host "Exporting to: $outputFile" -ForegroundColor Green

    try {
        $failedUsersReport | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
        Write-Host "Report exported successfully!" -ForegroundColor Green

        # Show summary statistics
        Write-Host "`nDepartment Summary:" -ForegroundColor Cyan
        $failedUsersReport | Group-Object Department | Sort-Object Count -Descending | Select-Object @{N='Department';E={$_.Name}}, Count | Format-Table -AutoSize

        Write-Host "Manager Summary:" -ForegroundColor Cyan
        $failedUsersReport | Group-Object ManagerName | Sort-Object Count -Descending | Select-Object @{N='Manager';E={$_.Name}}, Count | Format-Table -AutoSize

    } catch {
        Write-Error "Failed to export report: $_"
    }
} else {
    Write-Host "`nNo failed users found in the specified simulations." -ForegroundColor Green
}

# Disconnect
Write-Host "`nDisconnecting from Microsoft Graph..." -ForegroundColor Cyan
Disconnect-MgGraph
Write-Host "Done!" -ForegroundColor Green
