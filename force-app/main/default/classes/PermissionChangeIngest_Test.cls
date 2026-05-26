@IsTest
private class PermissionChangeIngest_Test {
    @IsTest
    static void enqueue_doesNotFailScanRun() {
        Id runId = ScanRunService.start('Manual Scan');

        Test.startTest();
        System.enqueueJob(new PermissionChangeIngest(runId));
        Test.stopTest();

        SecOps_Scan_Run__c run = [SELECT Status__c, Error_Log__c FROM SecOps_Scan_Run__c WHERE Id = :runId];
        System.assertNotEquals('Failed', run.Status__c, 'PermissionChangeIngest must not fail the Scan_Run');
        System.assert(
            run.Error_Log__c != null && run.Error_Log__c.contains('PermissionChangeIngest'),
            'Log should reference PermissionChangeIngest'
        );
    }

    @IsTest
    static void windowStartOverride_runsCleanly() {
        Id runId = ScanRunService.start('Scheduled');

        Test.startTest();
        System.enqueueJob(new PermissionChangeIngest(runId, Datetime.now().addDays(-7)));
        Test.stopTest();

        SecOps_Scan_Run__c run = [SELECT Status__c, Error_Log__c FROM SecOps_Scan_Run__c WHERE Id = :runId];
        System.assertNotEquals('Failed', run.Status__c, 'Override window must not fail the Scan_Run');
        System.assert(
            run.Error_Log__c != null && run.Error_Log__c.contains('assignments in window'),
            'Override path should still log the assignment count'
        );
    }

    @IsTest
    static void buildLog_formatsCount() {
        System.assertEquals(
            'PermissionChangeIngest: 5 assignments in window',
            PermissionChangeIngest.buildLog(5),
            'Log line formats the windowed count'
        );
    }
}
