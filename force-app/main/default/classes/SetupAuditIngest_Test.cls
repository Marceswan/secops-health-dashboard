@IsTest
private class SetupAuditIngest_Test {
    @IsTest
    static void enqueue_doesNotFailScanRun() {
        Id runId = ScanRunService.start('Manual Scan');

        Test.startTest();
        System.enqueueJob(new SetupAuditIngest(runId));
        Test.stopTest();

        SecOps_Scan_Run__c run = [SELECT Status__c, Error_Log__c FROM SecOps_Scan_Run__c WHERE Id = :runId];
        System.assertNotEquals('Failed', run.Status__c, 'SetupAuditIngest must not fail the Scan_Run');
        System.assert(
            run.Error_Log__c != null && run.Error_Log__c.contains('SetupAuditIngest'),
            'Log should reference SetupAuditIngest'
        );
    }
}
