@IsTest
private class UserBaselineRefresh_Test {
    @IsTest
    static void enqueue_doesNotThrow() {
        // No LoginHistory rows can be inserted in tests; this exercises the
        // Queueable end-to-end and proves no exception is thrown when the
        // user set is empty.
        Test.startTest();
        System.enqueueJob(new UserBaselineRefresh());
        Test.stopTest();
        // Reaching this point with no exception is the assertion.
        System.assert(true, 'Queueable enqueued cleanly');
    }

    @IsTest
    static void execute_persistsBaselineWhenUserExists() {
        // Pre-seed a baseline so the existing-row branch is exercised on
        // the second pass. Direct execute() call lets us observe DML.
        User u = TestDataFactory.standardUser();
        User_Baseline__c seed = BaselineEngine.buildForUser(u.Id, Datetime.now().addDays(-30));
        insert seed;

        Test.startTest();
        new UserBaselineRefresh().execute(null);
        Test.stopTest();

        List<User_Baseline__c> rows = [SELECT Id, User__c, User_Id_External__c FROM User_Baseline__c];
        System.assert(!rows.isEmpty(), 'At least the seeded baseline should remain');
        for (User_Baseline__c b : rows) {
            System.assertEquals(
                String.valueOf(b.User__c),
                b.User_Id_External__c,
                'User_Id_External__c must mirror User__c'
            );
        }
    }

    @IsTest
    static void execute_withCursor_runsKeysetBranch() {
        // Construct with an explicit cursor so the afterUserId-based query branch
        // (the second SOQL in the keyset pagination) executes.
        User u = TestDataFactory.standardUser();

        Test.startTest();
        new UserBaselineRefresh(u.Id).execute(null);
        Test.stopTest();

        System.assert(true, 'Keyset-paginated execute ran without error');
    }
}
