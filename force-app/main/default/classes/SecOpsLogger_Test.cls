@IsTest
private class SecOpsLogger_Test {
    @IsTest
    static void log_appendsMessageToScanRun() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();

        Test.startTest();
        SecOpsLogger.log(run.Id, 'hello from logger');
        Test.stopTest();

        SecOps_Scan_Run__c reloaded = [SELECT Error_Log__c FROM SecOps_Scan_Run__c WHERE Id = :run.Id];
        System.assert(
            reloaded.Error_Log__c != null && reloaded.Error_Log__c.contains('hello from logger'),
            'Logger should append the message to the run log'
        );
    }
}
