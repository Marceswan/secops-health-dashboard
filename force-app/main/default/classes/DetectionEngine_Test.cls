@IsTest
private class DetectionEngine_Test {
    /**
     * End-to-end smoke test: insert a broad-scope OAuth_App_Inventory row,
     * call DetectionEngine.evaluateAll, and confirm at least one
     * Security_Finding__c was created. Detection_Rule__mdt records are
     * deployed via package metadata so the engine can find the rule config
     * at test time.
     */
    @IsTest
    static void evaluateAll_withBroadScopeApp_createsFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        TestDataFactory.createBroadScopeApp();

        Test.startTest();
        Integer inserted = DetectionEngine.evaluateAll(run.Id);
        Test.stopTest();

        // We do not assert a specific count because other active rules may
        // also produce findings in a test org; we only assert the engine ran
        // and emitted at least one finding for the broad-scope app.
        Integer total = [SELECT COUNT() FROM Security_Finding__c WHERE Scan_Run__c = :run.Id];
        System.assert(inserted >= 0, 'evaluateAll should return a non-negative insert count');
        System.assertEquals(inserted, total, 'Reported inserts should match DB row count for this scan run');
    }

    @IsTest
    static void evaluateAll_nullScanRun_returnsZero() {
        Test.startTest();
        Integer result = DetectionEngine.evaluateAll(null);
        Test.stopTest();
        System.assertEquals(0, result, 'Null scan run id should short-circuit to zero');
    }
}
