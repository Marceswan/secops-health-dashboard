/**
 * Detects which optional Salesforce security capabilities the running org has
 * available (Event Log File, Real-Time Event Monitoring, etc.) so detection
 * rules can self-disable when their data source is missing.
 *
 * Results are cached into SecOps_Capability__mdt via MetadataService so the
 * rest of the platform can read the answer without redoing the probe.
 */
public with sharing class CapabilityProbe {
    /**
     * Snapshot of capability probe results.
     */
    public class ProbeResult {
        @AuraEnabled
        public Boolean hasEventLogFile;
        @AuraEnabled
        public Boolean hasRealTimeEventMonitoring;
        @AuraEnabled
        public Datetime lastProbed;

        public ProbeResult() {
            this.hasEventLogFile = false;
            this.hasRealTimeEventMonitoring = false;
            this.lastProbed = Datetime.now();
        }
    }

    /**
     * Run the probe right now and return the result. Does not persist; caller
     * is responsible for invoking MetadataService.upsertSingletonCapability if
     * they want the answer cached.
     */
    public static ProbeResult runNow() {
        ProbeResult result = new ProbeResult();
        result.hasEventLogFile = detectEventLogFile();
        result.hasRealTimeEventMonitoring = detectRealTimeEventMonitoring();
        result.lastProbed = Datetime.now();
        return result;
    }

    /**
     * Returns true when EventLogFile is queryable in this org.
     * A describe check is enough — if the SObject is not licensed the describe
     * either returns null or isQueryable() is false.
     */
    public static Boolean detectEventLogFile() {
        try {
            Schema.DescribeSObjectResult d = describeIfPresent('EventLogFile');
            return d != null && d.isQueryable();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Returns true when Real-Time Event Monitoring storage objects are present.
     * We probe LoginEventStream because every RTEM-licensed org exposes it.
     */
    public static Boolean detectRealTimeEventMonitoring() {
        try {
            Schema.DescribeSObjectResult d = describeIfPresent('LoginEventStream');
            return d != null && d.isQueryable();
        } catch (Exception e) {
            return false;
        }
    }

    private static Schema.DescribeSObjectResult describeIfPresent(String sObjectApiName) {
        Map<String, Schema.SObjectType> gd = Schema.getGlobalDescribe();
        Schema.SObjectType t = gd.get(sObjectApiName);
        if (t == null) {
            return null;
        }
        return t.getDescribe();
    }
}
