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

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Security

# Import required modules
Write-Host "Importing Microsoft Graph modules..." -ForegroundColor Cyan
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Security

# Connect to Microsoft Graph
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Write-Host "Required scopes: SecurityEvents.Read.All, User.Read.All" -ForegroundColor Yellow

try {
    Connect-MgGraph -Scopes "SecurityEvents.Read.All", "User.Read.All" -NoWelcome
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
        $uri = "https://graph.microsoft.com/v1.0/security/attackSimulation/simulations/$SimulationId"
        $simulations = @(Invoke-MgGraphRequest -Uri $uri -Method GET)
    } else {
        # Get all simulations from the last X days
        $startDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $uri = "https://graph.microsoft.com/v1.0/security/attackSimulation/simulations?`$filter=createdDateTime ge $startDate&`$orderby=createdDateTime desc"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET
        $simulations = $response.value
    }

    Write-Host "Found $($simulations.Count) simulation(s) to process" -ForegroundColor Green
} catch {
    Write-Error "Failed to retrieve simulations: $_"
    Disconnect-MgGraph
    exit 1
}

# Process each simulation
foreach ($simulation in $simulations) {
    $simName = $simulation.displayName
    $simId = $simulation.id
    $simStatus = $simulation.status

    Write-Host "`nProcessing simulation: $simName (ID: $simId, Status: $simStatus)" -ForegroundColor Cyan

    try {
        # Get the simulation report
        $reportUri = "https://graph.microsoft.com/v1.0/security/attackSimulation/simulations/$simId/report"
        $report = Invoke-MgGraphRequest -Uri $reportUri -Method GET

        # Get user simulation details
        if ($report.simulationUsers -and $report.simulationUsers.Count -gt 0) {
            Write-Host "Found $($report.simulationUsers.Count) users in simulation" -ForegroundColor Yellow

            # Filter for compromised users
            $compromisedUsers = $report.simulationUsers | Where-Object { $_.isCompromised -eq $true }
            Write-Host "Found $($compromisedUsers.Count) compromised (failed) users" -ForegroundColor $(if ($compromisedUsers.Count -gt 0) { "Red" } else { "Green" })

            # Process each compromised user
            foreach ($simUser in $compromisedUsers) {
                $userId = $simUser.simulationUser.userId
                $userEmail = $simUser.simulationUser.email
                $userDisplayName = $simUser.simulationUser.displayName

                Write-Host "  Processing user: $userDisplayName ($userEmail)" -ForegroundColor Gray

                try {
                    # Get detailed user information including manager
                    $userDetails = Get-MgUser -UserId $userId -Property "displayName,mail,department,jobTitle,officeLocation,manager" -ExpandProperty "manager" -ErrorAction SilentlyContinue

                    # Get manager separately if expand didn't work
                    $managerName = "N/A"
                    $managerEmail = "N/A"
                    try {
                        $manager = Get-MgUserManager -UserId $userId -ErrorAction SilentlyContinue
                        if ($manager) {
                            $managerDetails = Get-MgUser -UserId $manager.Id -Property "displayName,mail" -ErrorAction SilentlyContinue
                            $managerName = $managerDetails.DisplayName
                            $managerEmail = $managerDetails.Mail
                        }
                    } catch {
                        Write-Verbose "Could not retrieve manager for $userDisplayName"
                    }

                    # Create report object
                    $reportObject = [PSCustomObject]@{
                        SimulationName = $simName
                        SimulationId = $simId
                        SimulationStatus = $simStatus
                        UserDisplayName = $userDisplayName
                        UserEmail = $userEmail
                        UserId = $userId
                        Department = if ($userDetails.Department) { $userDetails.Department } else { "N/A" }
                        JobTitle = if ($userDetails.JobTitle) { $userDetails.JobTitle } else { "N/A" }
                        OfficeLocation = if ($userDetails.OfficeLocation) { $userDetails.OfficeLocation } else { "N/A" }
                        ManagerName = $managerName
                        ManagerEmail = $managerEmail
                        CompromisedDateTime = $simUser.compromisedDateTime
                        ReportedPhish = if ($simUser.reportedPhishDateTime) { "Yes" } else { "No" }
                        ReportedPhishDateTime = if ($simUser.reportedPhishDateTime) { $simUser.reportedPhishDateTime } else { "N/A" }
                        TrainingsAssigned = $simUser.assignedTrainingsCount
                        TrainingsCompleted = $simUser.completedTrainingsCount
                        TrainingsInProgress = $simUser.inProgressTrainingsCount
                    }

                    $failedUsersReport += $reportObject

                } catch {
                    Write-Warning "Could not retrieve details for user $userDisplayName : $_"

                    # Add minimal record
                    $reportObject = [PSCustomObject]@{
                        SimulationName = $simName
                        SimulationId = $simId
                        SimulationStatus = $simStatus
                        UserDisplayName = $userDisplayName
                        UserEmail = $userEmail
                        UserId = $userId
                        Department = "ERROR"
                        JobTitle = "ERROR"
                        OfficeLocation = "ERROR"
                        ManagerName = "ERROR"
                        ManagerEmail = "ERROR"
                        CompromisedDateTime = $simUser.compromisedDateTime
                        ReportedPhish = if ($simUser.reportedPhishDateTime) { "Yes" } else { "No" }
                        ReportedPhishDateTime = if ($simUser.reportedPhishDateTime) { $simUser.reportedPhishDateTime } else { "N/A" }
                        TrainingsAssigned = $simUser.assignedTrainingsCount
                        TrainingsCompleted = $simUser.completedTrainingsCount
                        TrainingsInProgress = $simUser.inProgressTrainingsCount
                    }

                    $failedUsersReport += $reportObject
                }
            }
        } else {
            Write-Host "No user data found in simulation report" -ForegroundColor Yellow
        }

    } catch {
        Write-Warning "Failed to retrieve report for simulation $simName : $_"
    }
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
