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
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        Datetime cutoff = Datetime.now().addHours(-24);

        for (PermissionSetAssignment psa : [
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
        ]) {
            Security_Finding__c f = FindingFactory.build(
                ctx.scanRunId,
                getDeveloperName(),
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
