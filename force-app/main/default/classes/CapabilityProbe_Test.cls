@isTest
private class CapabilityProbe_Test {
    @isTest
    static void runNow_returnsNonNullSnapshot() {
        Test.startTest();
        CapabilityProbe.ProbeResult result = CapabilityProbe.runNow();
        Test.stopTest();

        System.assertNotEquals(null, result, 'runNow() should always return a ProbeResult');
        System.assertNotEquals(null, result.hasEventLogFile, 'hasEventLogFile should be non-null');
        System.assertNotEquals(
            null,
            result.hasRealTimeEventMonitoring,
            'hasRealTimeEventMonitoring should be non-null'
        );
        System.assertNotEquals(null, result.lastProbed, 'lastProbed should be set');
    }

    @isTest
    static void detectEventLogFile_returnsBoolean() {
        Test.startTest();
        Boolean has = CapabilityProbe.detectEventLogFile();
        Test.stopTest();

        System.assertNotEquals(null, has, 'detectEventLogFile must return a non-null Boolean');
    }

    @isTest
    static void detectRealTimeEventMonitoring_returnsBoolean() {
        Test.startTest();
        Boolean has = CapabilityProbe.detectRealTimeEventMonitoring();
        Test.stopTest();

        System.assertNotEquals(null, has, 'detectRealTimeEventMonitoring must return a non-null Boolean');
    }
}
