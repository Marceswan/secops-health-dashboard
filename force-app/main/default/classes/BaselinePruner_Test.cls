@IsTest
private class BaselinePruner_Test {
    @IsTest
    static void run_noBaselines_noException() {
        Test.startTest();
        BaselinePruner.run();
        Test.stopTest();
        System.assert(true, 'BaselinePruner ran without exception against empty data');
    }
}
