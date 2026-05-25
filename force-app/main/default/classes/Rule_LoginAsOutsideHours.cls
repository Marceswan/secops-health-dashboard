/**
 * Detection rule: flags LoginAs events (admin impersonation of another user)
 * that occurred outside business hours (08:00-18:00 local server time).
 * Off-hours admin LoginAs is a high-signal anomaly because legitimate
 * support sessions almost always happen during business hours.
 *
 * Source data is Security_Event__c rows staged by EventLogFileIngest from
 * EventLogFile rows of type LoginAs. Requires the EventLogFile capability.
 */
public with sharing class Rule_LoginAsOutsideHours implements DetectionRule {
    /** Lookback window in hours. */
    private static final Integer WINDOW_HOURS = 24;
    /** Business hours are 08:00 (inclusive) to 18:00 (exclusive). */
    private static final Integer BUSINESS_HOUR_START = 8;
    private static final Integer BUSINESS_HOUR_END = 18;

    public String getDeveloperName() {
        return 'LoginAs_Outside_Hours';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return ctx != null && ctx.hasEventLogFile == true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        Datetime cutoff = Datetime.now().addHours(-WINDOW_HOURS);

        List<Security_Event__c> events = [
            SELECT Id, User__c, Event_Time__c, Source_Json__c
            FROM Security_Event__c
            WHERE Event_Type__c = 'LoginAs' AND Event_Time__c >= :cutoff
            LIMIT 5000
        ];

        for (Security_Event__c evt : events) {
            if (evt.Event_Time__c == null) {
                continue;
            }
            Integer hr = evt.Event_Time__c.hour();
            if (hr >= BUSINESS_HOUR_START && hr < BUSINESS_HOUR_END) {
                continue;
            }
            findings.add(
                FindingFactory.build(
                    ctx.scanRunId,
                    getDeveloperName(),
                    'Login Anomaly',
                    SecOpsConstants.SEVERITY_MEDIUM,
                    evt.User__c,
                    null,
                    String.valueOf(evt.Id),
                    new Map<String, Object>{ 'loginAsTime' => evt.Event_Time__c, 'hour' => hr }
                )
            );
        }
        return findings;
    }
}
