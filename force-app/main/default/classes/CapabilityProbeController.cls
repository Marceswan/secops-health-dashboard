/**
 * AuraEnabled facade over CapabilityProbe + MetadataService so LWCs can
 * trigger a fresh probe ("Run probe" button) or read the cached singleton
 * (capability badge in the header).
 */
public with sharing class CapabilityProbeController {
    /**
     * Run the probe now, persist the result to SecOps_Capability__mdt (via the
     * async Metadata API), and return the snapshot to the caller. The async
     * deploy means subsequent reads may briefly return the previous values.
     */
    @AuraEnabled
    public static CapabilityProbe.ProbeResult runProbe() {
        CapabilityProbe.ProbeResult result = CapabilityProbe.runNow();
        MetadataService.upsertSingletonCapability(result);
        return result;
    }

    /**
     * Read the cached capability singleton without re-probing.
     * Returns a fresh ProbeResult populated from SecOps_Capability__mdt.Current,
     * or a default-false ProbeResult if the record has not been created yet.
     */
    @AuraEnabled(cacheable=true)
    public static CapabilityProbe.ProbeResult readCapability() {
        CapabilityProbe.ProbeResult result = new CapabilityProbe.ProbeResult();
        List<SecOps_Capability__mdt> rows = [
            SELECT EventLogFile_Available__c, RealTimeEventMonitoring_Available__c, Last_Probed__c
            FROM SecOps_Capability__mdt
            WHERE DeveloperName = :SecOpsConstants.CAPABILITY_DEVELOPER_NAME
            LIMIT 1
        ];
        if (!rows.isEmpty()) {
            SecOps_Capability__mdt row = rows[0];
            result.hasEventLogFile = row.EventLogFile_Available__c == true;
            result.hasRealTimeEventMonitoring = row.RealTimeEventMonitoring_Available__c == true;
            if (row.Last_Probed__c != null) {
                result.lastProbed = row.Last_Probed__c;
            }
        }
        return result;
    }
}
