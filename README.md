# Security Reporting Scripts

PowerShell scripts for Microsoft 365 security reporting and analysis.

## Scripts

### Export-PhishingSimulationReport.ps1

Export Attack Simulation Training failures with user department and manager information.

**Features:**
- Retrieves failed users from Microsoft 365 Attack Simulation Training campaigns
- Enriches data with department and manager information from Microsoft Entra ID
- Exports to CSV for reporting
- Provides summary statistics by department and manager

**Requirements:**
- Microsoft.Graph PowerShell SDK
- Permissions: SecurityEvents.Read.All, User.Read.All

**Usage:**
```powershell
# Last 30 days (default)
.\Export-PhishingSimulationReport.ps1

# Last 7 days
.\Export-PhishingSimulationReport.ps1 -DaysBack 7

# Last 90 days with custom output path
.\Export-PhishingSimulationReport.ps1 -DaysBack 90 -OutputPath "C:\Reports"
```

**Installation:**
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

## License

MIT
