@IsTest
private class BaselinePruner_Test {
    @IsTest
    static void run_noBaselines_noException() {
        Test.startTest();
        BaselinePruner.run();
        Test.stopTest();
        System.assert(true, 'BaselinePruner ran without exception against empty data');
    }

    @IsTest
    static void run_deletesBaselinesForInactiveUsers() {
        // Create and deactivate a user (setup DML) isolated via runAs to avoid
        // MIXED_DML with the non-setup User_Baseline__c insert below.
        User u;
        System.runAs(new User(Id = UserInfo.getUserId())) {
            u = TestDataFactory.standardUser();
            u.IsActive = false;
            update u;
        }
        // Build a fully-populated baseline (sets required fields like
        // Last_Refreshed__c) then attach it to the inactive user.
        User_Baseline__c b = BaselineEngine.buildForUser(u.Id, Datetime.now().addDays(-1));
        b.User__c = u.Id;
        b.User_Id_External__c = u.Id;
        insert b;

        Test.startTest();
        BaselinePruner.run();
        Test.stopTest();

        System.assertEquals(
            0,
            [SELECT COUNT() FROM User_Baseline__c WHERE Id = :b.Id],
            'Baseline for an inactive user should be pruned'
        );
    }
}
