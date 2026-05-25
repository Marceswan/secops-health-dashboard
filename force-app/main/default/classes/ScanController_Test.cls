@IsTest
private class ScanController_Test {
    @IsTest
    static void startScan_returnsNonNullIdAndCreatesRun() {
        Test.startTest();
        Id runId = ScanController.startScan();
        Test.stopTest();

        System.assertNotEquals(null, runId, 'startScan should return a Scan_Run Id');
        SecOps_Scan_Run__c run = [
            SELECT Id, Status__c, Run_Type__c
            FROM SecOps_Scan_Run__c
            WHERE Id = :runId
        ];
        System.assertEquals('Manual Scan', run.Run_Type__c);
        System.assertEquals('Running', run.Status__c);
    }

    @IsTest
    static void readLastRun_returnsMostRecent() {
        Id firstId = ScanRunService.start('Manual Scan');
        // Force a different CreatedDate ordering by inserting a second run later.
        Id secondId = ScanRunService.start('Scheduled');

        Test.startTest();
        SecOps_Scan_Run__c last = ScanController.readLastRun();
        Test.stopTest();

        System.assertNotEquals(null, last, 'readLastRun should not return null when rows exist');
        System.assertEquals(secondId, last.Id, 'Most recent run by CreatedDate should be returned');
    }

    @IsTest
    static void readLastRun_returnsNullWhenEmpty() {
        SecOps_Scan_Run__c last = ScanController.readLastRun();
        System.assertEquals(null, last, 'Empty org returns null');
    }
}
