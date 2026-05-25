@isTest
private class CapabilityProbeController_Test {
    @isTest
    static void runProbe_returnsResult() {
        Test.startTest();
        CapabilityProbe.ProbeResult result = CapabilityProbeController.runProbe();
        Test.stopTest();

        System.assertNotEquals(null, result, 'runProbe should return a ProbeResult');
        System.assertNotEquals(null, result.lastProbed, 'lastProbed should be populated');
    }

    @isTest
    static void readCapability_returnsResult() {
        Test.startTest();
        CapabilityProbe.ProbeResult result = CapabilityProbeController.readCapability();
        Test.stopTest();

        System.assertNotEquals(null, result, 'readCapability should always return a ProbeResult');
        System.assertNotEquals(null, result.hasEventLogFile, 'hasEventLogFile should default to non-null');
        System.assertNotEquals(
            null,
            result.hasRealTimeEventMonitoring,
            'hasRealTimeEventMonitoring should default to non-null'
        );
    }
}
