/**
 * Detection rule: scans recent SetupAuditTrail entries for MFA being
 * disabled for one or more users. MFA changes are tracked in the audit
 * trail rather than a dedicated object, so we pattern-match Display and
 * Action against known phrasing.
 */
public with sharing class Rule_MfaDisabledForUser implements DetectionRule {
    public String getDeveloperName() {
        return 'MFA_Disabled_For_User';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        Datetime cutoff = Datetime.now().addDays(-7);

        // SetupAuditTrail.Display is not filterable in SOQL. Pre-filter by
        // CreatedDate and Action (which IS filterable), then match Display
        // patterns in Apex below.
        List<SetupAuditTrail> rows = [
            SELECT Id, Action, Display, CreatedDate, CreatedById
            FROM SetupAuditTrail
            WHERE CreatedDate >= :cutoff
            LIMIT 1000
        ];
        return evaluateRows(ctx, rows);
    }

    @TestVisible
    private static List<Security_Finding__c> evaluateRows(DetectionContext ctx, List<SetupAuditTrail> rows) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        for (SetupAuditTrail s : rows) {
            String disp = s.Display == null ? '' : s.Display;
            String act = s.Action == null ? '' : s.Action;
            Boolean matches =
                disp.containsIgnoreCase('Multi-Factor Authentication') && disp.containsIgnoreCase('disabled') ||
                (disp.containsIgnoreCase('MFA') && disp.containsIgnoreCase('disabled')) ||
                act.containsIgnoreCase('Disabled Multi-Factor');
            if (!matches) {
                continue;
            }
            findings.add(
                FindingFactory.build(
                    ctx.scanRunId,
                    'MFA_Disabled_For_User',
                    'Setup Change',
                    SecOpsConstants.SEVERITY_HIGH,
                    s.CreatedById,
                    null,
                    String.valueOf(s.Id),
                    new Map<String, Object>{
                        'action' => s.Action,
                        'display' => s.Display,
                        'changedAt' => s.CreatedDate
                    }
                )
            );
        }
        return findings;
    }
}
