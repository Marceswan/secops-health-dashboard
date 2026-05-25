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
                    Status__c = 'Completed',
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
}
