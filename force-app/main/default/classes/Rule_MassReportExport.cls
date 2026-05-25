/**
 * Detection rule: flags users who exported more than 50 reports in the last
 * 24 hours. High-volume report export from a single user is a leading
 * indicator of data exfiltration, especially when paired with login anomalies
 * or new OAuth tokens on the same user.
 *
 * Source data is Security_Event__c rows staged by EventLogFileIngest from
 * EventLogFile rows of type ReportExport. Requires the EventLogFile
 * capability (Event Monitoring / Shield) — gated by the DetectionEngine via
 * Required_Capability__c='EventLogFile'.
 */
public with sharing class Rule_MassReportExport implements DetectionRule {
    /** Lookback window in hours. */
    private static final Integer WINDOW_HOURS = 24;
    /** Minimum export count per user in the window to raise a finding. */
    private static final Integer EXPORT_THRESHOLD = 50;

    public String getDeveloperName() {
        return 'Mass_Report_Export';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return ctx != null && ctx.hasEventLogFile == true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        Datetime cutoff = Datetime.now().addHours(-WINDOW_HOURS);

        List<AggregateResult> rows = [
            SELECT User__c userId, COUNT(Id) cnt
            FROM Security_Event__c
            WHERE Event_Type__c = 'ReportExport' AND Event_Time__c >= :cutoff AND User__c != NULL
            GROUP BY User__c
            HAVING COUNT(Id) > :EXPORT_THRESHOLD
            LIMIT 200
        ];

        Long nowMs = Datetime.now().getTime();
        for (AggregateResult ar : rows) {
            Id userId = (Id) ar.get('userId');
            Integer exportCount = (Integer) ar.get('cnt');
            findings.add(
                FindingFactory.build(
                    ctx.scanRunId,
                    getDeveloperName(),
                    'OAuth Risk',
                    SecOpsConstants.SEVERITY_HIGH,
                    userId,
                    null,
                    'mass-export-' + userId + '-' + nowMs,
                    new Map<String, Object>{ 'exportCount' => exportCount, 'windowHours' => WINDOW_HOURS }
                )
            );
        }
        return findings;
    }
}
