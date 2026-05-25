/**
 * Detection rule: scans SetupAuditTrail for the last 7 days for any entry
 * that mentions Session Timeout. The Display field stores a free-text
 * narrative ("changed from X to Y") that cannot be parsed reliably in SOQL,
 * so this rule is intentionally conservative — any session timeout change
 * fires; triage is responsible for confirming whether the new value
 * exceeds the org policy (typically &gt; 8h).
 */
public with sharing class Rule_SessionTimeoutExtended implements DetectionRule {
    /** Lookback window in days. */
    private static final Integer LOOKBACK_DAYS = 7;

    public String getDeveloperName() {
        return 'Session_Timeout_Extended';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        Datetime cutoff = Datetime.now().addDays(-LOOKBACK_DAYS);

        // SetupAuditTrail.Display is not filterable in SOQL; match in Apex.
        for (SetupAuditTrail s : [
            SELECT Id, Action, Display, CreatedDate, CreatedById
            FROM SetupAuditTrail
            WHERE CreatedDate >= :cutoff
            LIMIT 1000
        ]) {
            String disp = s.Display == null ? '' : s.Display;
            if (!disp.containsIgnoreCase('Session Timeout')) {
                continue;
            }
            Security_Finding__c f = FindingFactory.build(
                ctx.scanRunId,
                getDeveloperName(),
                'Setup Change',
                SecOpsConstants.SEVERITY_MEDIUM,
                s.CreatedById,
                null,
                String.valueOf(s.Id),
                new Map<String, Object>{
                    'action' => s.Action,
                    'display' => s.Display,
                    'changedAt' => s.CreatedDate,
                    'note' => 'Conservative match: any Session Timeout change fires; triage to confirm new value > 8h'
                }
            );
            f.Risk_Score__c = 50;
            findings.add(f);
        }
        return findings;
    }
}
