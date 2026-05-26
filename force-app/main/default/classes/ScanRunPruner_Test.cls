@IsTest
private class ScanRunPruner_Test {
    @IsTest
    static void prune_smallSet_noDeletion() {
        List<SecOps_Scan_Run__c> runs = new List<SecOps_Scan_Run__c>();
        Datetime base = Datetime.now().addDays(-5);
        for (Integer i = 0; i < 5; i++) {
            runs.add(
                new SecOps_Scan_Run__c(
                    Started_At__c = base.addMinutes(i),
                    Status__c = 'Complete',
                    Run_Type__c = 'Scheduled'
                )
            );
        }
        insert runs;

        Test.startTest();
        Database.executeBatch(new ScanRunPruner(), 200);
        Test.stopTest();

        Integer remaining = [SELECT COUNT() FROM SecOps_Scan_Run__c];
        System.assertEquals(5, remaining, 'Should retain all runs when count is below KEEP_COUNT');
    }

    @IsTest
    static void execute_deletesScope() {
        List<SecOps_Scan_Run__c> runs = new List<SecOps_Scan_Run__c>();
        for (Integer i = 0; i < 3; i++) {
            runs.add(
                new SecOps_Scan_Run__c(
                    Started_At__c = Datetime.now().addDays(-30),
                    Status__c = 'Complete',
                    Run_Type__c = 'Scheduled'
                )
            );
        }
        insert runs;

        Test.startTest();
        new ScanRunPruner().execute(null, runs);
        Test.stopTest();

        System.assertEquals(
            0,
            [SELECT COUNT() FROM SecOps_Scan_Run__c WHERE Id IN :runs],
            'execute should delete the records in scope'
        );
    }
}
