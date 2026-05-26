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

    @isTest
    static void mapCapability_populatedRow_mapsAllFields() {
        Datetime probed = Datetime.now().addHours(-1);
        SecOps_Capability__mdt row = new SecOps_Capability__mdt(
            EventLogFile_Available__c = true,
            RealTimeEventMonitoring_Available__c = true,
            Last_Probed__c = probed
        );

        CapabilityProbe.ProbeResult result = CapabilityProbeController.mapCapability(
            new List<SecOps_Capability__mdt>{ row }
        );

        System.assertEquals(true, result.hasEventLogFile, 'EventLogFile flag should map through');
        System.assertEquals(true, result.hasRealTimeEventMonitoring, 'RTEM flag should map through');
        System.assertEquals(probed, result.lastProbed, 'Last probed should map through');
    }

    @isTest
    static void mapCapability_emptyRows_returnsDefaults() {
        CapabilityProbe.ProbeResult result = CapabilityProbeController.mapCapability(
            new List<SecOps_Capability__mdt>()
        );
        System.assertEquals(false, result.hasEventLogFile, 'Default EventLogFile should be false');
        System.assertEquals(false, result.hasRealTimeEventMonitoring, 'Default RTEM should be false');
    }
}
