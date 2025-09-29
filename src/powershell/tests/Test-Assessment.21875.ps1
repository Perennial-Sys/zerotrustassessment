<#
.SYNOPSIS

#>

function Test-Assessment-21875{
    [ZtTest(
    	Category = 'Access control',
    	ImplementationCost = 'Medium',
    	Pillar = 'Identity',
    	RiskLevel = 'Medium',
    	SfiPillar = 'Protect identities and secrets',
    	TenantType = ('Workforce','External'),
    	TestId = 21875,
    	Title = 'Tenant has all External organizations allowed to collaborate as Connected Organization',
    	UserImpact = 'Medium'
    )]
    [CmdletBinding()]
    param(
        $Database
    )

    Write-PSFMessage '🟦 Start' -Tag Test -Level VeryVerbose

    $activity = 'Checking entitlement management assignment policies for external users'
    Write-ZtProgress -Activity $activity -Status 'Querying assignment policies'

    # Q1: Retrieve assignment policies for all access packages that target external users
    $sql = @"
    SELECT
        ap.id as AccessPackageId,
        ap.displayName as AccessPackageName,
        apap.id as AssignmentPolicyId,
        apap.displayName as AssignmentPolicyName,
        apap.requestorSettings.allowedTargetScope as allowedTargetScope
    FROM main.AccessPackage ap
    LEFT JOIN main.AccessPackageAssignmentPolicy apap ON apap.accessPackage.id = ap.id
    WHERE apap.requestorSettings.allowedTargetScope IN ('specificConnectedOrganizationUsers', 'allConfiguredConnectedOrganizationUsers', 'allExternalUsers')
    ORDER BY ap.displayName, apap.displayName
"@

    $results = Invoke-DatabaseQuery -Database $Database -Sql $sql

    # Initialize result variables
    $failed = @()
    $investigate = @()
    $passed = @()

    $testResultMarkdown = ''

    if ($results.Count -eq 0) {
        $testResultMarkdown = 'No assignment policies found that target external users.'
        $testPassed = $true
    } else {
        # Process results according to pass/fail logic
        foreach ($result in $results) {
            switch ($result.allowedTargetScope) {
                'allExternalUsers' {
                    $failed += $result
                }
                'allConfiguredConnectedOrganizationUsers' {
                    $investigate += $result
                }
                'specificConnectedOrganizationUsers' {
                    $passed += $result
                }
            }
        }

        # Determine overall test result based on pass/fail logic
        if ($failed.Count -gt 0) {
            $testResultMarkdown = '❌ Assignment policies without connected organization restrictions were found'
            $testPassed = $false
        } elseif ($investigate.Count -gt 0) {
            $testResultMarkdown = '⚠️ Assignment policies that allow any connected organization were found'
            $testPassed = $false
        } else {
            $testResultMarkdown = '✅ All assignment policies targeting external users are restricted to specific connected organizations'
            $testPassed = $true
        }
    }

    # Build detailed results markdown
    $mdDetails = ''

    # Helper function to build markdown table for a category
    $buildMarkdownTable = {
        param($items, $title, $icon)
        if ($items.Count -gt 0) {
            $section = "`n## $icon $title`n`n"
            $section += "| Access Package | Assignment Policy | Target Scope |`n"
            $section += "| :--- | :--- | :--- |`n"
            foreach ($item in $items) {
                $accessPackageLink = 'https://entra.microsoft.com/#view/Microsoft_AAD_ERM/DashboardBlade/~/elmEntitlement/menuId/'
                $section += "| [$(Get-SafeMarkdown($item.AccessPackageName))]($accessPackageLink) | $(Get-SafeMarkdown($item.AssignmentPolicyName)) | $($item.allowedTargetScope) |`n"
            }
            return $section
        }
        return ''
    }

    # Build sections for each category
    $mdDetails += & $buildMarkdownTable $failed 'Policies allowing all external users (FAIL)' '❌'
    $mdDetails += & $buildMarkdownTable $investigate 'Policies allowing all configured connected organizations (INVESTIGATE)' '⚠️'
    $mdDetails += & $buildMarkdownTable $passed 'Policies restricted to specific connected organizations (PASS)' '✅'

    # Add summary statistics
    if ($results.Count -gt 0) {
        $mdDetails += "`n## Summary`n`n"
        $mdDetails += "- **Total policies evaluated:** $($results.Count)`n"
        $mdDetails += "- **Policies allowing all external users:** $($failed.Count)`n"
        $mdDetails += "- **Policies allowing all configured connected organizations:** $($investigate.Count)`n"
        $mdDetails += "- **Policies restricted to specific connected organizations:** $($passed.Count)`n"
    }

    $testResultMarkdown += $mdDetails

    $params = @{
        TestId             = '21875'
        Status             = $testPassed
        Result             = $testResultMarkdown
    }

    Add-ZtTestResultDetail @params
}
