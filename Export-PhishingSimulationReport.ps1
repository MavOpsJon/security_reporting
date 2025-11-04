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
    # Get per-simulation user data using the correct API endpoint
    Write-Host "`nRetrieving detailed user data for simulation..." -ForegroundColor Cyan

    $simulationUsersUri = "https://graph.microsoft.com/beta/security/attackSimulation/simulations/$simId/report/simulationUsers"
    $simulationUsersResponse = Invoke-MgGraphRequest -Uri $simulationUsersUri -Method GET
    $simulationUsers = $simulationUsersResponse.value

    Write-Host "Found $($simulationUsers.Count) total users in simulation '$simName'" -ForegroundColor Cyan

    # Filter for users who were compromised (clicked/opened the phishing simulation)
    $compromisedUsers = $simulationUsers | Where-Object {
        $_.isCompromised -eq $true
    }

    Write-Host "Found $($compromisedUsers.Count) compromised users in this simulation" -ForegroundColor $(if ($compromisedUsers.Count -gt 0) { "Red" } else { "Green" })

    if ($compromisedUsers.Count -eq 0) {
        Write-Host "No users were compromised in the selected simulation '$simName'." -ForegroundColor Green
        Write-Host "This simulation had a 100% success rate!" -ForegroundColor Green
        Disconnect-MgGraph
        exit 0
    }

    # Process each compromised user
    foreach ($simUser in $compromisedUsers) {
        # Extract user information from the simulation user object
        $userEmail = $simUser.userPrincipalName
        $userDisplayName = $simUser.displayName
        $userId = $simUser.userId

        # Extract simulation-specific data
        $isCompromised = $simUser.isCompromised
        $reportedPhish = $simUser.reportedPhish
        $eventsCount = if ($simUser.eventsCount) { $simUser.eventsCount } else { 0 }
        $trainingStatus = if ($simUser.trainingStatus) { $simUser.trainingStatus } else { "N/A" }
        $assignedTrainingsCount = if ($simUser.assignedTrainingsCount) { $simUser.assignedTrainingsCount } else { 0 }
        $completedTrainingsCount = if ($simUser.completedTrainingsCount) { $simUser.completedTrainingsCount } else { 0 }
        $inProgressTrainingsCount = if ($simUser.inProgressTrainingsCount) { $simUser.inProgressTrainingsCount } else { 0 }

        # Extract event details (actions taken)
        $userActions = "N/A"
        if ($simUser.simulationEvents -and $simUser.simulationEvents.Count -gt 0) {
            $userActions = ($simUser.simulationEvents | ForEach-Object { $_.eventName }) -join ", "
        }

        Write-Host "  Processing compromised user: $userDisplayName ($userEmail)" -ForegroundColor Gray

        try {
            # Get detailed user information from Entra ID
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

            # Create report object with simulation-specific data
            $reportObject = [PSCustomObject]@{
                SimulationName = $simName
                UserDisplayName = $userDisplayName
                UserEmail = $userEmail
                UserId = $userId
                IsCompromised = $isCompromised
                ReportedPhish = $reportedPhish
                UserActions = $userActions
                EventsCount = $eventsCount
                TrainingStatus = $trainingStatus
                AssignedTrainings = $assignedTrainingsCount
                CompletedTrainings = $completedTrainingsCount
                InProgressTrainings = $inProgressTrainingsCount
                Department = if ($userDetails.department) { $userDetails.department } else { "N/A" }
                JobTitle = if ($userDetails.jobTitle) { $userDetails.jobTitle } else { "N/A" }
                OfficeLocation = if ($userDetails.officeLocation) { $userDetails.officeLocation } else { "N/A" }
                ManagerName = $managerName
                ManagerEmail = $managerEmail
            }

            $failedUsersReport += $reportObject

        } catch {
            Write-Warning "Could not retrieve details for user $userDisplayName : $_"

            # Add minimal record
            $reportObject = [PSCustomObject]@{
                SimulationName = $simName
                UserDisplayName = $userDisplayName
                UserEmail = $userEmail
                UserId = $userId
                IsCompromised = $isCompromised
                ReportedPhish = $reportedPhish
                UserActions = $userActions
                EventsCount = $eventsCount
                TrainingStatus = $trainingStatus
                AssignedTrainings = $assignedTrainingsCount
                CompletedTrainings = $completedTrainingsCount
                InProgressTrainings = $inProgressTrainingsCount
                Department = "Unable to retrieve"
                JobTitle = "Unable to retrieve"
                OfficeLocation = "Unable to retrieve"
                ManagerName = "Unable to retrieve"
                ManagerEmail = "Unable to retrieve"
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
