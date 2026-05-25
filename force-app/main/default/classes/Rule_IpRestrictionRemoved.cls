/**
 * Detection rule: scans SetupAuditTrail for the last 7 days for entries
 * that mention Login IP Range deletions or removals. Removing IP ranges
 * weakens network-layer access controls, so each matching audit entry
 * is surfaced for review.
 */
public with sharing class Rule_IpRestrictionRemoved implements DetectionRule {
    /** Lookback window in days. */
    private static final Integer LOOKBACK_DAYS = 7;

    public String getDeveloperName() {
        return 'IP_Restriction_Removed';
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
            if (
                !disp.containsIgnoreCase('Login IP Range') ||
                (!disp.containsIgnoreCase('delete') && !disp.containsIgnoreCase('removed'))
            ) {
                continue;
            }
            Security_Finding__c f = FindingFactory.build(
                ctx.scanRunId,
                getDeveloperName(),
                'Setup Change',
                SecOpsConstants.SEVERITY_HIGH,
                s.CreatedById,
                null,
                String.valueOf(s.Id),
                new Map<String, Object>{ 'action' => s.Action, 'display' => s.Display, 'changedAt' => s.CreatedDate }
            );
            f.Risk_Score__c = 75;
            findings.add(f);
        }
        return findings;
    }
}
