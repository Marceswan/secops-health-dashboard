/**
 * @AuraEnabled controller backing the SecOps posture dashboard LWCs.
 *
 * Exposes three read-only methods:
 *   - getRiskTrend       : daily Critical/High finding counts for the last N days
 *   - getAppInventorySummary : at-a-glance OAuth app counts
 *   - getTopRisks        : top N users or apps by finding count
 *
 * All methods are cacheable and shaped as primitive maps/lists so the LWCs
 * can consume them without DTO classes.
 */
public with sharing class PostureController {
    private static final Integer DEFAULT_DAYS = 90;
    private static final Integer DEFAULT_TOP = 10;

    /**
     * Daily counts of Critical and High severity findings over a rolling window.
     *
     * Returns one entry per day across the requested window (inclusive of today),
     * even for days with no findings (counts are zero-filled).
     *
     * @param days size of the trend window; defaults to 90 when null or <= 0
     * @return list of maps with keys: date (yyyy-MM-dd string), criticalCount, highCount
     */
    @AuraEnabled(cacheable=true)
    public static List<Map<String, Object>> getRiskTrend(Integer days) {
        Integer windowDays = days == null || days <= 0 ? DEFAULT_DAYS : days;

        Date startDate = Date.today().addDays(-(windowDays - 1));
        Datetime startDt = Datetime.newInstance(startDate, Time.newInstance(0, 0, 0, 0));

        // Aggregate findings by day and severity
        Map<String, Map<String, Integer>> byDay = new Map<String, Map<String, Integer>>();
        for (AggregateResult ar : [
            SELECT DAY_ONLY(CreatedDate) day, Severity__c sev, COUNT(Id) cnt
            FROM Security_Finding__c
            WHERE CreatedDate >= :startDt AND Severity__c IN ('Critical', 'High')
            GROUP BY DAY_ONLY(CreatedDate), Severity__c
        ]) {
            Date d = (Date) ar.get('day');
            String key = formatDate(d);
            String sev = (String) ar.get('sev');
            Integer cnt = (Integer) ar.get('cnt');
            if (!byDay.containsKey(key)) {
                byDay.put(key, new Map<String, Integer>{ 'Critical' => 0, 'High' => 0 });
            }
            byDay.get(key).put(sev, cnt);
        }

        // Zero-fill every day in the window so the chart has even spacing
        List<Map<String, Object>> result = new List<Map<String, Object>>();
        for (Integer i = 0; i < windowDays; i++) {
            Date d = startDate.addDays(i);
            String key = formatDate(d);
            Map<String, Integer> counts = byDay.get(key);
            Integer critical = counts == null ? 0 : counts.get('Critical');
            Integer high = counts == null ? 0 : counts.get('High');
            if (critical == null) {
                critical = 0;
            }
            if (high == null) {
                high = 0;
            }
            result.add(new Map<String, Object>{ 'date' => key, 'criticalCount' => critical, 'highCount' => high });
        }
        return result;
    }

    /**
     * High-level OAuth app inventory counters for the dashboard tile row.
     *
     * @return map with keys: totalApps, newIn30Days, newIn90Days, broadScopeCount, staleCount
     */
    @AuraEnabled(cacheable=true)
    public static Map<String, Integer> getAppInventorySummary() {
        Datetime now = Datetime.now();
        Datetime thirtyDaysAgo = now.addDays(-30);
        Datetime ninetyDaysAgo = now.addDays(-90);

        Integer totalApps = [SELECT COUNT() FROM OAuth_App_Inventory__c];

        Integer newIn30Days = [
            SELECT COUNT()
            FROM OAuth_App_Inventory__c
            WHERE First_Seen__c >= :thirtyDaysAgo
        ];

        Integer newIn90Days = [
            SELECT COUNT()
            FROM OAuth_App_Inventory__c
            WHERE First_Seen__c >= :ninetyDaysAgo
        ];

        Integer broadScopeCount = [
            SELECT COUNT()
            FROM OAuth_App_Inventory__c
            WHERE Risk_Flags__c INCLUDES ('Broad Scope')
        ];

        Integer staleCount = [
            SELECT COUNT()
            FROM OAuth_App_Inventory__c
            WHERE Last_Seen__c < :ninetyDaysAgo
        ];

        return new Map<String, Integer>{
            'totalApps' => totalApps,
            'newIn30Days' => newIn30Days,
            'newIn90Days' => newIn90Days,
            'broadScopeCount' => broadScopeCount,
            'staleCount' => staleCount
        };
    }

    /**
     * Top subjects (users or apps) ranked by open + closed finding count.
     *
     * @param dimension 'user' or 'app'; anything else returns an empty list
     * @param limitSize maximum rows to return; defaults to 10
     * @return list of maps with keys: id, name, findingCount
     */
    @AuraEnabled(cacheable=true)
    public static List<Map<String, Object>> getTopRisks(String dimension, Integer limitSize) {
        Integer effective = limitSize == null || limitSize <= 0 ? DEFAULT_TOP : limitSize;
        List<Map<String, Object>> result = new List<Map<String, Object>>();

        if (dimension == 'user') {
            for (AggregateResult ar : [
                SELECT Subject_User__c subj, Subject_User__r.Name uname, COUNT(Id) cnt
                FROM Security_Finding__c
                WHERE Subject_User__c != NULL
                GROUP BY Subject_User__c, Subject_User__r.Name
                ORDER BY COUNT(Id) DESC
                LIMIT :effective
            ]) {
                result.add(
                    new Map<String, Object>{
                        'id' => ar.get('subj'),
                        'name' => ar.get('uname'),
                        'findingCount' => ar.get('cnt')
                    }
                );
            }
        } else if (dimension == 'app') {
            for (AggregateResult ar : [
                SELECT Subject_App__c subj, Subject_App__r.Name aname, COUNT(Id) cnt
                FROM Security_Finding__c
                WHERE Subject_App__c != NULL
                GROUP BY Subject_App__c, Subject_App__r.Name
                ORDER BY COUNT(Id) DESC
                LIMIT :effective
            ]) {
                result.add(
                    new Map<String, Object>{
                        'id' => ar.get('subj'),
                        'name' => ar.get('aname'),
                        'findingCount' => ar.get('cnt')
                    }
                );
            }
        }
        return result;
    }

    private static String formatDate(Date d) {
        String y = String.valueOf(d.year());
        String m = String.valueOf(d.month()).leftPad(2, '0');
        String day = String.valueOf(d.day()).leftPad(2, '0');
        return y + '-' + m + '-' + day;
    }
}
