/**
 * Detection rule: flags Bulk API jobs initiated from a client name (or source
 * name) the user has never used in the prior 30 days. A new Bulk API client
 * on a previously-quiet user is a strong indicator of credential theft or
 * unauthorized integration deployment.
 *
 * Source data is Security_Event__c rows staged by EventLogFileIngest from
 * EventLogFile rows of type BulkApi. The client is best-effort parsed from
 * Source_Json__c using CLIENT_NAME, then CLIENT, then SOURCE_NAME.
 *
 * Requires the EventLogFile capability (Event Monitoring / Shield).
 */
public with sharing class Rule_BulkApiFromNewClient implements DetectionRule {
    /** Recent window in hours (events being evaluated). */
    private static final Integer RECENT_HOURS = 24;
    /** Baseline window in days for prior-client lookup. */
    private static final Integer BASELINE_DAYS = 30;
    /** Keys checked in order to extract the client identifier from Source_Json__c. */
    private static final List<String> CLIENT_KEYS = new List<String>{ 'CLIENT_NAME', 'CLIENT', 'SOURCE_NAME' };

    public String getDeveloperName() {
        return 'Bulk_Api_From_New_Client';
    }

    public Boolean isApplicable(DetectionContext ctx) {
        return ctx != null && ctx.hasEventLogFile == true;
    }

    public List<Security_Finding__c> evaluate(DetectionContext ctx) {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();

        Datetime recentCutoff = Datetime.now().addHours(-RECENT_HOURS);
        Datetime baselineStart = Datetime.now().addDays(-BASELINE_DAYS);

        List<Security_Event__c> recent = [
            SELECT Id, User__c, Event_Time__c, Source_Json__c
            FROM Security_Event__c
            WHERE Event_Type__c = 'BulkApi' AND Event_Time__c >= :recentCutoff AND User__c != NULL
            LIMIT 5000
        ];
        if (recent.isEmpty()) {
            return findings;
        }

        Set<Id> userIds = new Set<Id>();
        for (Security_Event__c evt : recent) {
            userIds.add(evt.User__c);
        }

        // Build per-user set of historical clients in the [30d, 24h) window.
        List<Security_Event__c> historical = [
            SELECT User__c, Source_Json__c
            FROM Security_Event__c
            WHERE
                Event_Type__c = 'BulkApi'
                AND Event_Time__c >= :baselineStart
                AND Event_Time__c < :recentCutoff
                AND User__c IN :userIds
            LIMIT 50000
        ];
        Map<Id, Set<String>> historicalByUser = new Map<Id, Set<String>>();
        for (Security_Event__c evt : historical) {
            String client = extractClient(evt.Source_Json__c);
            if (client == null) {
                continue;
            }
            if (!historicalByUser.containsKey(evt.User__c)) {
                historicalByUser.put(evt.User__c, new Set<String>());
            }
            historicalByUser.get(evt.User__c).add(client);
        }

        for (Security_Event__c evt : recent) {
            String client = extractClient(evt.Source_Json__c);
            if (client == null) {
                continue;
            }
            Set<String> known = historicalByUser.get(evt.User__c);
            if (known != null && known.contains(client)) {
                continue;
            }
            findings.add(
                FindingFactory.build(
                    ctx.scanRunId,
                    getDeveloperName(),
                    'OAuth Risk',
                    SecOpsConstants.SEVERITY_HIGH,
                    evt.User__c,
                    null,
                    String.valueOf(evt.Id),
                    new Map<String, Object>{
                        'client' => client,
                        'eventTime' => evt.Event_Time__c,
                        'baselineDays' => BASELINE_DAYS
                    }
                )
            );
        }
        return findings;
    }

    /**
     * Best-effort client extraction from the Source_Json__c payload. Tries
     * CLIENT_NAME, CLIENT, SOURCE_NAME in order and returns the first
     * non-blank string value. Returns null if none are present or the JSON
     * is unparseable.
     */
    private String extractClient(String sourceJson) {
        if (String.isBlank(sourceJson)) {
            return null;
        }
        Map<String, Object> parsed;
        try {
            parsed = (Map<String, Object>) JSON.deserializeUntyped(sourceJson);
        } catch (Exception e) {
            return null;
        }
        if (parsed == null) {
            return null;
        }
        for (String key : CLIENT_KEYS) {
            Object v = parsed.get(key);
            if (v == null) {
                continue;
            }
            String s = String.valueOf(v);
            if (!String.isBlank(s)) {
                return s.trim();
            }
        }
        return null;
    }
}
