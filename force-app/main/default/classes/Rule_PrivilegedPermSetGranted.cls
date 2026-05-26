/**
 * Detection rule: flags PermissionSet assignments granted in the last 24
 * hours where the target permission set carries broad admin capability —
 * Modify All Data, Manage Users, or a label that includes "admin". These
 * grants effectively elevate the assignee to a privileged role and should
 * be reviewed every time they occur.
 */
public with sharing class Rule_PrivilegedPermSetGranted implements DetectionRule {
    public String getDeveloperName() {
        return 'Privileged_PermSet_Granted';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        Datetime cutoff = Datetime.now().addHours(-24);

        List<PermissionSetAssignment> rows = [
            SELECT
                Id,
                AssigneeId,
                PermissionSetId,
                PermissionSet.Label,
                PermissionSet.PermissionsModifyAllData,
                PermissionSet.PermissionsManageUsers,
                SystemModstamp
            FROM PermissionSetAssignment
            WHERE
                SystemModstamp >= :cutoff
                AND (PermissionSet.PermissionsModifyAllData = TRUE
                OR PermissionSet.PermissionsManageUsers = TRUE
                OR PermissionSet.Label LIKE '%admin%')
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
            Security_Finding__c f = FindingFactory.build(
                ctx.scanRunId,
                'Privileged_PermSet_Granted',
                'Privilege Escalation',
                SecOpsConstants.SEVERITY_HIGH,
                psa.AssigneeId,
                null,
                String.valueOf(psa.Id),
                new Map<String, Object>{
                    'permissionSetLabel' => psa.PermissionSet.Label,
                    'permissionSetId' => psa.PermissionSetId,
                    'modifyAllData' => psa.PermissionSet.PermissionsModifyAllData,
                    'manageUsers' => psa.PermissionSet.PermissionsManageUsers,
                    'grantedAt' => psa.SystemModstamp
                }
            );
            f.Risk_Score__c = 75;
            findings.add(f);
        }
        return findings;
    }
}
