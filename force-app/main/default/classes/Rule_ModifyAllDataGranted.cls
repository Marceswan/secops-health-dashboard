/**
 * Detection rule: flags PermissionSet assignments that grant Modify All Data
 * or View All Data, indicating a privilege escalation event worth reviewing
 * within the 24-hour lookback window.
 */
public with sharing class Rule_ModifyAllDataGranted implements DetectionRule {
    public String getDeveloperName() {
        return 'ModifyAllData_Granted';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        Datetime cutoff = Datetime.now().addHours(-24);

        List<PermissionSetAssignment> rows = [
            SELECT
                AssigneeId,
                PermissionSetId,
                PermissionSet.Label,
                PermissionSet.PermissionsModifyAllData,
                PermissionSet.PermissionsViewAllData,
                SystemModstamp
            FROM PermissionSetAssignment
            WHERE
                SystemModstamp >= :cutoff
                AND (PermissionSet.PermissionsModifyAllData = TRUE
                OR PermissionSet.PermissionsViewAllData = TRUE)
            LIMIT 5000
        ];
        return evaluateRows(ctx, rows);
    }

    /**
     * Build a finding per privileged assignment. Separated from the SOQL so tests
     * can pass in-memory PermissionSetAssignment rows; the production filter lives
     * in evaluate()'s query.
     */
    @TestVisible
    private static List<Security_Finding__c> evaluateRows(DetectionContext ctx, List<PermissionSetAssignment> rows) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        for (PermissionSetAssignment psa : rows) {
            findings.add(
                FindingFactory.build(
                    ctx.scanRunId,
                    'ModifyAllData_Granted',
                    'Privilege Escalation',
                    SecOpsConstants.SEVERITY_HIGH,
                    psa.AssigneeId,
                    null,
                    String.valueOf(psa.Id),
                    new Map<String, Object>{
                        'permissionSetLabel' => psa.PermissionSet.Label,
                        'modifyAllData' => psa.PermissionSet.PermissionsModifyAllData,
                        'viewAllData' => psa.PermissionSet.PermissionsViewAllData,
                        'grantedAt' => psa.SystemModstamp
                    }
                )
            );
        }
        return findings;
    }
}
