/**
 * Shared constants for the SecOps Health package.
 * Centralizes magic strings/numbers so rule code stays readable.
 */
public with sharing class SecOpsConstants {
    // Capability metadata
    public static final String CAPABILITY_DEVELOPER_NAME = 'Current';

    // Risk score bands
    public static final Integer RISK_CRITICAL = 90;
    public static final Integer RISK_HIGH = 70;
    public static final Integer RISK_MEDIUM = 40;
    public static final Integer RISK_LOW = 10;

    // Default lookback windows (hours)
    public static final Integer DEFAULT_LOOKBACK_HOURS = 24;
    public static final Integer BASELINE_LOOKBACK_DAYS = 30;

    // Status values for Security_Finding__c.Status__c (must match restricted picklist on schema)
    public static final String STATUS_NEW = 'New';
    public static final String STATUS_ACKNOWLEDGED = 'Acknowledged';
    public static final String STATUS_REMEDIATED = 'Remediated';
    public static final String STATUS_DISMISSED = 'Dismissed';

    // Severity tokens
    public static final String SEVERITY_CRITICAL = 'Critical';
    public static final String SEVERITY_HIGH = 'High';
    public static final String SEVERITY_MEDIUM = 'Medium';
    public static final String SEVERITY_LOW = 'Low';

    // Scan run status (must match restricted picklist on SecOps_Scan_Run__c.Status__c)
    public static final String SCAN_STATUS_RUNNING = 'Running';
    public static final String SCAN_STATUS_COMPLETE = 'Complete';
    public static final String SCAN_STATUS_FAILED = 'Failed';

    // Scan run types (must match restricted picklist on SecOps_Scan_Run__c.Run_Type__c)
    public static final String RUN_TYPE_MANUAL = 'Manual Scan';
    public static final String RUN_TYPE_SCHEDULED = 'Scheduled';
    public static final String RUN_TYPE_REALTIME = 'Real-Time Event';

    // Detection windows
    public static final Integer LOGIN_HISTORY_WINDOW_DAYS = 180;
    public static final Integer BASELINE_WARMUP_THRESHOLD = 20;
    public static final Integer QUEUEABLE_CHUNK_SIZE = 200;

    private SecOpsConstants() {
        // no instances
    }
}
