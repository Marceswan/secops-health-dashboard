@IsTest
private class EventLogFileIngest_Test {
    /**
     * On a scratch org / dev sandbox without Shield, CapabilityProbe reports
     * hasEventLogFile=false. The ingest must log a "skipped" line and exit
     * cleanly without failing the parent Scan_Run.
     */
    @IsTest
    static void skipsWhenEventLogFileNotLicensed() {
        Id runId = ScanRunService.start('Manual Scan');

        Test.startTest();
        System.enqueueJob(new EventLogFileIngest(runId));
        Test.stopTest();

        SecOps_Scan_Run__c run = [
            SELECT Status__c, Error_Log__c
            FROM SecOps_Scan_Run__c
            WHERE Id = :runId
        ];
        System.assertNotEquals(
            'Failed',
            run.Status__c,
            'EventLogFileIngest must not fail the Scan_Run on non-Shield orgs'
        );
        System.assert(
            run.Error_Log__c != null && run.Error_Log__c.contains('EventLogFileIngest'),
            'Log should reference EventLogFileIngest'
        );
    }

    /**
     * Verify the explicit-window constructor wires through without error.
     */
    @IsTest
    static void windowedConstructor_runsCleanly() {
        Id runId = ScanRunService.start('Manual Scan');

        Test.startTest();
        System.enqueueJob(new EventLogFileIngest(runId, Datetime.now().addDays(-1)));
        Test.stopTest();

        SecOps_Scan_Run__c run = [SELECT Status__c FROM SecOps_Scan_Run__c WHERE Id = :runId];
        System.assertNotEquals('Failed', run.Status__c, 'Windowed constructor must not fail the Scan_Run');
    }
}
