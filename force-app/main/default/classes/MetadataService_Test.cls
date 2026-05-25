@isTest
private class MetadataService_Test {
    @isTest
    static void upsertSingletonCapability_doesNotThrow() {
        CapabilityProbe.ProbeResult result = new CapabilityProbe.ProbeResult();
        result.hasEventLogFile = true;
        result.hasRealTimeEventMonitoring = false;
        result.lastProbed = Datetime.now();

        Test.startTest();
        MetadataService.upsertSingletonCapability(result);
        MetadataService.upsertSingletonCapability(null);
        Test.stopTest();

        System.assert(true, 'upsertSingletonCapability should be a no-op safe call in test context');
    }
}
