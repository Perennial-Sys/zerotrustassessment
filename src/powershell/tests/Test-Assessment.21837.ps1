<#
.SYNOPSIS

#>

function Test-Assessment-21837{
    [ZtTest(
    	Category = 'Device management',
    	ImplementationCost = 'Low',
    	Pillar = 'Identity',
    	RiskLevel = 'High',
    	SfiPillar = 'Protect identities and secrets',
    	TenantType = ('Workforce'),
    	TestId = 21837,
    	Title = 'Limit the maximum number of devices per user to 10',
    	UserImpact = 'Medium'
    )]
    [CmdletBinding()]
    param(
        # Database connection for internal user queries
        $Database
    )

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $activity = 'Checking maximum number of devices per user limit'
    Write-ZtProgress -Activity $activity -Status "Getting policy"

    # Retrieve device registration policy
    Write-ZtProgress -Activity $activity -Status 'Getting device registration policy'
    $policy = Invoke-ZtGraphRequest -RelativeUri 'policies/deviceRegistrationPolicy' -ApiVersion 'beta'
    $userQuota = $null
    if ($policy) { $userQuota = $policy.userDeviceQuota }

    # Evaluate compliance
    $passed = $false
    if ($null -eq $userQuota) {
        $testResultMarkdown = '**Policy not found.** Unable to retrieve maximum device quota.'
    }
    elseif ($userQuota -le 10) {
        $passed = $true
        $testResultMarkdown = "**Compliant**: Current device limit is $userQuota devices per user. No action required."
    }
    elseif ($userQuota -le 20) {
        $testResultMarkdown = "**Minor Non-compliance**: Current device limit is $userQuota devices per user (≤20). Consider reducing to 10 or fewer."
    }
    else {
        $testResultMarkdown = "**Significant Non-compliance**: Current device limit is $userQuota devices per user (>20). Reduce limit to 10 or fewer."
    }

    # Simplified check: find users exceeding the configured device quota via internal database query
    Write-ZtProgress -Activity $activity -Status 'Fetching all users from database'
    $sql = 'SELECT id FROM [User]'
    $users = Invoke-DatabaseQuery -Database $Database -Sql $sql

    $exceeding = @()
    foreach ($u in $users) {
        $count = Invoke-ZtGraphRequest -RelativeUri "users/$($u.id)/registeredDevices/`$count" -ApiVersion 'v1.0' -ConsistencyLevel 'eventual'
        if ($count -gt $userQuota) {
            $exceeding += [PSCustomObject]@{ UserId = $u.id; DeviceCount = $count }
        }
    }
    # Build markdown summary for offenders
    $mdUsers = "`n## Users exceeding device limit ($userQuota)`n`n"
    if ($exceeding.Count -eq 0) {
        $mdUsers += 'All users are within the configured limit.'
    }
    else {
        $mdUsers += '| UserId | DeviceCount |`n| :----- | :---------- |`n'
        foreach ($e in $exceeding) {
            $mdUsers += "| $($e.UserId) | $($e.DeviceCount) |`n"
        }
    }
    $testResultMarkdown += $mdUsers

    Add-ZtTestResultDetail -TestId '21837' -Title 'Limit the maximum number of devices per user to 10' `
        -UserImpact Medium -Risk High -ImplementationCost Low `
        -AppliesTo Identity -Tag Identity `
        -Status $passed -Result $testResultMarkdown
}
