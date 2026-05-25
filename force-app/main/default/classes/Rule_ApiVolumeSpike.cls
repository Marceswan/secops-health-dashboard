/**
 * Detection rule: flags users whose API call volume today exceeds 2x their
 * 90-day trailing average, with a noise floor of 100 calls so low-volume
 * service accounts do not generate false positives on normal-looking days.
 *
 * Source data is Security_Event__c rows staged by EventLogFileIngest from
 * EventLogFile rows of type ApiTotalUsage. Requires the EventLogFile
 * capability (Event Monitoring / Shield).
 */
public with sharing class Rule_ApiVolumeSpike implements DetectionRule {
    /** Minimum today's-count required to fire (suppresses low-volume noise). */
    private static final Integer MIN_TODAY_COUNT = 100;
    /** Today's count must exceed this multiplier of the 90-day average. */
    private static final Decimal SPIKE_MULTIPLIER = 2.0;
    /** Trailing window in days for baseline average. */
    private static final Integer BASELINE_DAYS = 90;

    public String getDeveloperName() {
        return 'Api_Volume_Spike';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return ctx != null && ctx.hasEventLogFile == true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();

        Datetime todayCutoff = Datetime.now().addHours(-24);
        Datetime baselineCutoff = Datetime.now().addDays(-BASELINE_DAYS);

        // Today's count per user
        Map<Id, Integer> todayByUser = new Map<Id, Integer>();
        for (AggregateResult ar : [
            SELECT User__c userId, COUNT(Id) cnt
            FROM Security_Event__c
            WHERE Event_Type__c = 'ApiTotalUsage' AND Event_Time__c >= :todayCutoff AND User__c != NULL
            GROUP BY User__c
            LIMIT 5000
        ]) {
            todayByUser.put((Id) ar.get('userId'), (Integer) ar.get('cnt'));
        }
        if (todayByUser.isEmpty()) {
            return findings;
        }

        // 90-day total per user (we will divide by BASELINE_DAYS for the avg)
        Map<Id, Integer> totalByUser = new Map<Id, Integer>();
        for (AggregateResult ar : [
            SELECT User__c userId, COUNT(Id) cnt
            FROM Security_Event__c
            WHERE Event_Type__c = 'ApiTotalUsage' AND Event_Time__c >= :baselineCutoff AND User__c != NULL
            GROUP BY User__c
            LIMIT 5000
        ]) {
            totalByUser.put((Id) ar.get('userId'), (Integer) ar.get('cnt'));
        }

        for (Id userId : todayByUser.keySet()) {
            Integer todayCount = todayByUser.get(userId);
            if (todayCount < MIN_TODAY_COUNT) {
                continue;
            }
            Integer total = totalByUser.containsKey(userId) ? totalByUser.get(userId) : 0;
            Decimal avg = Decimal.valueOf(total) / BASELINE_DAYS;
            Decimal threshold = avg * SPIKE_MULTIPLIER;
            if (Decimal.valueOf(todayCount) <= threshold) {
                continue;
            }
            findings.add(
                FindingFactory.build(
                    ctx.scanRunId,
                    getDeveloperName(),
                    'OAuth Risk',
                    SecOpsConstants.SEVERITY_MEDIUM,
                    userId,
                    null,
                    'api-spike-' + userId + '-' + Datetime.now().getTime(),
                    new Map<String, Object>{
                        'todayCount' => todayCount,
                        'baselineAvg' => avg,
                        'baselineDays' => BASELINE_DAYS,
                        'multiplier' => SPIKE_MULTIPLIER
                    }
                )
            );
        }
        return findings;
    }
}
