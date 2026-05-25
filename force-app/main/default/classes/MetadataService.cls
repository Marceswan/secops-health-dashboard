/**
 * Thin wrapper over the async Apex Metadata API used to upsert the singleton
 * SecOps_Capability__mdt.Current record from CapabilityProbe results.
 *
 * Custom Metadata writes are async: the caller cannot read-after-write in the
 * same transaction. UI flows should rely on the in-memory ProbeResult returned
 * by CapabilityProbe.runNow() until the deploy settles.
 */
public with sharing class MetadataService {
    /**
     * Upsert SecOps_Capability__mdt.Current with the probe snapshot.
     * No-op during test execution since Metadata.Operations.enqueueDeployment
     * is not supported in Apex test context.
     */
    public static void upsertSingletonCapability(CapabilityProbe.ProbeResult result) {
        if (result == null) {
            return;
        }

        Metadata.CustomMetadata cm = new Metadata.CustomMetadata();
        cm.fullName = 'SecOps_Capability__mdt.' + SecOpsConstants.CAPABILITY_DEVELOPER_NAME;
        cm.label = 'Current';

        cm.values.add(buildField('EventLogFile_Available__c', result.hasEventLogFile));
        cm.values.add(buildField('RealTimeEventMonitoring_Available__c', result.hasRealTimeEventMonitoring));
        cm.values.add(buildField('Last_Probed__c', result.lastProbed));

        Metadata.DeployContainer mdContainer = new Metadata.DeployContainer();
        mdContainer.addMetadata(cm);

        if (!Test.isRunningTest()) {
            Metadata.Operations.enqueueDeployment(mdContainer, null);
        }
    }

    private static Metadata.CustomMetadataValue buildField(String fieldApiName, Object value) {
        Metadata.CustomMetadataValue f = new Metadata.CustomMetadataValue();
        f.field = fieldApiName;
        f.value = value;
        return f;
    }
}
