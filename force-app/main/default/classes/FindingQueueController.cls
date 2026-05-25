/**
 * @AuraEnabled controller backing the SecOps finding queue LWC.
 *
 * Returns open Security_Finding__c rows for the dashboard. Open is defined
 * as Status__c in (New, Acknowledged). Sorted by Risk_Score__c desc and
 * CreatedDate desc so the most urgent findings appear first.
 */
public with sharing class FindingQueueController {
    /** Maximum rows returned to the queue UI. */
    private static final Integer DEFAULT_LIMIT = 200;

    /**
     * Lightweight DTO returned to the LWC. Field set is small so the queue
     * stays responsive even with hundreds of open findings.
     */
    public class FindingRow {
        @AuraEnabled
        public Id id;
        @AuraEnabled
        public String detectionRule;
        @AuraEnabled
        public String category;
        @AuraEnabled
        public String severity;
        @AuraEnabled
        public String status;
        @AuraEnabled
        public Decimal riskScore;
        @AuraEnabled
        public Id subjectUserId;
        @AuraEnabled
        public String subjectUserName;
        @AuraEnabled
        public Id subjectAppId;
        @AuraEnabled
        public String subjectAppName;
        @AuraEnabled
        public Datetime createdDate;
        @AuraEnabled
        public Id scanRunId;
    }

    /**
     * Return open findings for the queue UI, sorted by risk then recency.
     *
     * @param limitSize Optional override for max rows; defaults to 200.
     */
    @AuraEnabled(cacheable=true)
    public static List<FindingRow> getOpenFindings(Integer limitSize) {
        Integer effective = limitSize == null || limitSize <= 0 ? DEFAULT_LIMIT : limitSize;
        List<FindingRow> rows = new List<FindingRow>();

        for (Security_Finding__c f : [
            SELECT
                Id,
                Detection_Rule__c,
                Category__c,
                Severity__c,
                Status__c,
                Risk_Score__c,
                Subject_User__c,
                Subject_User__r.Name,
                Subject_App__c,
                Subject_App__r.Name,
                CreatedDate,
                Scan_Run__c
            FROM Security_Finding__c
            WHERE Status__c IN ('New', 'Acknowledged')
            WITH SECURITY_ENFORCED
            ORDER BY Risk_Score__c DESC NULLS LAST, CreatedDate DESC
            LIMIT :effective
        ]) {
            FindingRow r = new FindingRow();
            r.id = f.Id;
            r.detectionRule = f.Detection_Rule__c;
            r.category = f.Category__c;
            r.severity = f.Severity__c;
            r.status = f.Status__c;
            r.riskScore = f.Risk_Score__c;
            r.subjectUserId = f.Subject_User__c;
            r.subjectUserName = f.Subject_User__r == null ? null : f.Subject_User__r.Name;
            r.subjectAppId = f.Subject_App__c;
            r.subjectAppName = f.Subject_App__r == null ? null : f.Subject_App__r.Name;
            r.createdDate = f.CreatedDate;
            r.scanRunId = f.Scan_Run__c;
            rows.add(r);
        }
        return rows;
    }

    /**
     * Count of unresolved Critical-severity findings, for the home-page alerter LWC.
     * Filter is intentionally tight (Status = New AND Severity = Critical) so the
     * badge only lights up for findings that have not yet been triaged.
     */
    @AuraEnabled(cacheable=true)
    public static Integer getCriticalCount() {
        return [
            SELECT COUNT()
            FROM Security_Finding__c
            WHERE Status__c = 'New' AND Severity__c = :SecOpsConstants.SEVERITY_CRITICAL
        ];
    }
}
