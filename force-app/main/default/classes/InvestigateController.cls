/**
 * Investigation controller for the SecOps dashboard.
 *
 * Powers three investigation tools surfaced in the dashboard LWCs:
 *   - User timeline (mix of Security_Finding__c + LoginHistory rows)
 *   - Cross-user heatmap (findings counts grouped by user + category)
 *   - Per-finding baseline diff (which payload fields diverge from the
 *     user's User_Baseline__c)
 *
 * Methods are @AuraEnabled and side-effect free; they only read data.
 */
public with sharing class InvestigateController {
    /** Default lookback days when caller does not specify. */
    private static final Integer DEFAULT_DAYS = 30;
    /** Hard cap on rows returned to the timeline / heatmap UIs. */
    private static final Integer MAX_ROWS = 500;
    /** Default cap on users surfaced in the timeline user picker. */
    private static final Integer DEFAULT_USER_LIMIT = 100;

    /**
     * One row in a per-user timeline. Implements Comparable so a mixed list
     * (findings + LoginHistory) can be sorted by timestamp DESC.
     */
    public class TimelineEntry implements Comparable {
        @AuraEnabled
        public Datetime ts;
        @AuraEnabled
        public String entryType;
        @AuraEnabled
        public String label;
        @AuraEnabled
        public Id refId;
        @AuraEnabled
        public String severity;

        public Integer compareTo(Object other) {
            TimelineEntry o = (TimelineEntry) other;
            if (this.ts == null && o.ts == null) {
                return 0;
            }
            if (this.ts == null) {
                return 1;
            }
            if (o.ts == null) {
                return -1;
            }
            if (this.ts > o.ts) {
                return -1;
            }
            if (this.ts < o.ts) {
                return 1;
            }
            return 0;
        }
    }

    /**
     * Return active users for the timeline user picker. Cached because the
     * underlying set rarely changes mid-session.
     *
     * @param limitSize Optional override (max 200). Defaults to 100.
     */
    @AuraEnabled(cacheable=true)
    public static List<User> listActiveUsers(Integer limitSize) {
        Integer effective = limitSize == null || limitSize <= 0 ? DEFAULT_USER_LIMIT : limitSize;
        if (effective > 200) {
            effective = 200;
        }
        return [
            SELECT Id, Name, Username
            FROM User
            WHERE IsActive = TRUE
            WITH SECURITY_ENFORCED
            ORDER BY Name ASC
            LIMIT :effective
        ];
    }

    /**
     * Build a chronological per-user activity timeline: open and closed
     * Security_Finding__c rows for the user, plus successful and failed
     * LoginHistory rows in the same window. Sorted by timestamp DESC.
     */
    @AuraEnabled(cacheable=true)
    public static List<TimelineEntry> getTimelineForUser(Id userId, Integer days) {
        List<TimelineEntry> entries = new List<TimelineEntry>();
        if (userId == null) {
            return entries;
        }
        Integer effectiveDays = days == null || days <= 0 ? DEFAULT_DAYS : days;
        Datetime since = Datetime.now().addDays(-effectiveDays);

        for (Security_Finding__c f : [
            SELECT Id, CreatedDate, Detection_Rule__c, Category__c, Severity__c, Status__c
            FROM Security_Finding__c
            WHERE Subject_User__c = :userId AND CreatedDate >= :since
            WITH SECURITY_ENFORCED
            ORDER BY CreatedDate DESC
            LIMIT :MAX_ROWS
        ]) {
            TimelineEntry e = new TimelineEntry();
            e.ts = f.CreatedDate;
            e.entryType = 'Finding';
            e.label = f.Detection_Rule__c + ' (' + f.Category__c + ', ' + f.Status__c + ')';
            e.refId = f.Id;
            e.severity = f.Severity__c;
            entries.add(e);
        }

        for (LoginHistory lh : [
            SELECT Id, LoginTime, Status, SourceIp, CountryIso, Application
            FROM LoginHistory
            WHERE UserId = :userId AND LoginTime >= :since
            ORDER BY LoginTime DESC
            LIMIT :MAX_ROWS
        ]) {
            TimelineEntry e = new TimelineEntry();
            e.ts = lh.LoginTime;
            e.entryType = 'Login';
            String app = lh.Application == null ? 'Unknown' : lh.Application;
            String country = lh.CountryIso == null ? '--' : lh.CountryIso;
            e.label = 'Login ' + lh.Status + ' via ' + app + ' from ' + country + ' (' + lh.SourceIp + ')';
            e.refId = null;
            e.severity = lh.Status == 'Success' ? SecOpsConstants.SEVERITY_LOW : SecOpsConstants.SEVERITY_MEDIUM;
            entries.add(e);
        }

        entries.sort();
        return entries;
    }

    /**
     * Cross-user heatmap data: aggregate open + recent findings by user and
     * category for the given window. Returned as a list of plain maps so the
     * LWC can render it as a flat table without further reshaping.
     *
     * Each row: { userId, userName, category, count }.
     */
    @AuraEnabled(cacheable=true)
    public static List<Map<String, Object>> getCrossUserHeatmap(Integer days) {
        List<Map<String, Object>> rows = new List<Map<String, Object>>();
        Integer effectiveDays = days == null || days <= 0 ? DEFAULT_DAYS : days;
        Datetime since = Datetime.now().addDays(-effectiveDays);

        for (AggregateResult ar : [
            SELECT Subject_User__c userId, Subject_User__r.Name userName, Category__c category, COUNT(Id) cnt
            FROM Security_Finding__c
            WHERE CreatedDate >= :since AND Subject_User__c != NULL
            WITH SECURITY_ENFORCED
            GROUP BY Subject_User__c, Subject_User__r.Name, Category__c
            ORDER BY COUNT(Id) DESC
            LIMIT :MAX_ROWS
        ]) {
            Map<String, Object> row = new Map<String, Object>();
            row.put('userId', ar.get('userId'));
            row.put('userName', ar.get('userName'));
            row.put('category', ar.get('category'));
            row.put('count', ar.get('cnt'));
            rows.add(row);
        }
        return rows;
    }

    /**
     * Compare the Source_Event_Json__c payload on a finding to the subject
     * user's User_Baseline__c. Returns the list of field paths whose values
     * are NOT in the baseline set. Currently checks countryIso, /24 of
     * sourceIp, and application/AppName.
     */
    @AuraEnabled(cacheable=true)
    public static List<String> diffAgainstBaseline(Id findingId) {
        List<String> diff = new List<String>();
        if (findingId == null) {
            return diff;
        }
        List<Security_Finding__c> rows = [
            SELECT Id, Subject_User__c, Source_Event_Json__c
            FROM Security_Finding__c
            WHERE Id = :findingId
            WITH SECURITY_ENFORCED
            LIMIT 1
        ];
        if (rows.isEmpty()) {
            return diff;
        }
        Security_Finding__c f = rows[0];
        if (f.Subject_User__c == null || String.isBlank(f.Source_Event_Json__c)) {
            return diff;
        }
        User_Baseline__c baseline = BaselineEngine.getBaselineFor(f.Subject_User__c);
        if (baseline == null) {
            return diff;
        }

        Map<String, Object> payload;
        try {
            payload = (Map<String, Object>) JSON.deserializeUntyped(f.Source_Event_Json__c);
        } catch (Exception e) {
            return diff;
        }
        if (payload == null) {
            return diff;
        }

        Object countryObj = payload.get('countryIso');
        if (countryObj == null) {
            countryObj = payload.get('CountryIso');
        }
        if (countryObj != null) {
            String country = String.valueOf(countryObj);
            if (!BaselineEngine.isCountryInBaseline(baseline, country)) {
                diff.add('countryIso');
            }
        }

        Object ipObj = payload.get('sourceIp');
        if (ipObj == null) {
            ipObj = payload.get('SourceIp');
        }
        if (ipObj != null) {
            String ip24 = BaselineEngine.toIp24(String.valueOf(ipObj));
            if (ip24 != null && !BaselineEngine.isIp24InBaseline(baseline, ip24)) {
                diff.add('sourceIp');
            }
        }

        Object appObj = payload.get('application');
        if (appObj == null) {
            appObj = payload.get('AppName');
        }
        if (appObj == null) {
            appObj = payload.get('Application');
        }
        if (appObj != null) {
            String appName = String.valueOf(appObj);
            if (!BaselineEngine.isAppInBaseline(baseline, appName)) {
                diff.add('application');
            }
        }

        return diff;
    }
}
