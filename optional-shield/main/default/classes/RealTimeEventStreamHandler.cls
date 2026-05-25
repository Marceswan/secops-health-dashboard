/**
 * Shared handler for Real-Time Event Monitoring (RTEM) Platform Event triggers.
 *
 * Each entry point accepts a generic List<SObject> so this class can be
 * deployed without hard references to LoginEventStream / ApiEventStream /
 * ReportEventStream — those SObjects are only present in Shield-licensed orgs.
 *
 * For each inbound event we:
 *   1. Open a real-time Scan_Run (Run_Type__c = 'Real-Time Scan').
 *   2. Stage a Security_Event__c row that captures the event payload.
 *   3. Complete the Scan_Run with signals=1, findings=0.
 *
 * Exceptions are routed to ScanRunService.fail() so an upstream event flood
 * cannot poison the trigger framework.
 *
 * SHIPPING NOTE — lives in `optional-shield/`. Not part of the default package.
 */
public with sharing class RealTimeEventStreamHandler {
    private static final String RUN_TYPE = 'Real-Time Scan';

    public static void handleLoginEvents(List<SObject> events) {
        process(events, 'Login');
    }

    public static void handleApiEvents(List<SObject> events) {
        process(events, 'ApiTotalUsage');
    }

    public static void handleReportEvents(List<SObject> events) {
        process(events, 'ReportExport');
    }

    /**
     * Common processing path for all three stream types. Each event opens a
     * lightweight Scan_Run so downstream dashboards see real-time activity
     * alongside scheduled scans.
     */
    private static void process(List<SObject> events, String eventType) {
        if (events == null || events.isEmpty()) {
            return;
        }
        for (SObject evt : events) {
            Id runId = null;
            try {
                runId = ScanRunService.start(RUN_TYPE);
                Security_Event__c staged = buildSecurityEvent(evt, eventType);
                if (staged != null) {
                    Database.insert(staged, false);
                }
                ScanRunService.appendLog(runId, 'RealTimeEventStreamHandler: staged ' + eventType + ' event');
                ScanRunService.complete(runId, 1, 0);
            } catch (Exception e) {
                if (runId != null) {
                    ScanRunService.fail(runId, 'RealTimeEventStreamHandler(' + eventType + '): ' + e.getMessage());
                }
            }
        }
    }

    /**
     * Build a Security_Event__c from an inbound stream SObject. Reads fields
     * via the generic get() API so we don't hard-reference Shield-only types.
     */
    private static Security_Event__c buildSecurityEvent(SObject evt, String eventType) {
        if (evt == null) {
            return null;
        }
        Security_Event__c out = new Security_Event__c();
        out.Event_Type__c = eventType;
        out.Event_Time__c = readDatetime(evt, 'EventDate', Datetime.now());
        out.User__c = readUserId(evt);
        Map<String, Object> payload = evt.getPopulatedFieldsAsMap();
        String json = JSON.serialize(payload);
        out.Source_Json__c = json.length() > 32768 ? json.left(32768) : json;
        // Composite_Key__c is a formula — do not assign.
        return out;
    }

    private static Datetime readDatetime(SObject evt, String field, Datetime fallback) {
        try {
            Object v = evt.get(field);
            if (v instanceof Datetime) {
                return (Datetime) v;
            }
        } catch (Exception e) {
            // field not present on this stream type
        }
        return fallback;
    }

    private static Id readUserId(SObject evt) {
        for (String field : new List<String>{ 'UserId', 'SessionUserId', 'CreatedById' }) {
            try {
                Object v = evt.get(field);
                if (v instanceof Id) {
                    return (Id) v;
                }
                if (v instanceof String) {
                    String s = (String) v;
                    if (s.length() == 15 || s.length() == 18) {
                        return Id.valueOf(s);
                    }
                }
            } catch (Exception e) {
                // field not present on this stream type
            }
        }
        return null;
    }
}
