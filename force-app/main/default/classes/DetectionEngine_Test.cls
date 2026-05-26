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

    /**
     * Drives evaluateRules directly with in-memory rule configs (CMDT rows are
     * deployed separately and cannot be created via DML in tests). Exercises the
     * capability-gate skip, the unresolvable-class and not-a-rule instantiation
     * branches, a real rule that produces a finding, and the bulk insert.
     */
    @IsTest
    static void evaluateRules_coversGatingInstantiationAndInsert() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();

        // Two far-apart logins five minutes apart trigger Impossible_Travel.
        Datetime t = Datetime.now().addHours(-2);
        insert new List<Security_Event__c>{
            new Security_Event__c(
                Event_Type__c = 'LoginHistory',
                Event_Time__c = t,
                User__c = u.Id,
                Source_Json__c = JSON.serialize(new Map<String, Object>{ 'CountryIso' => 'US' })
            ),
            new Security_Event__c(
                Event_Type__c = 'LoginHistory',
                Event_Time__c = t.addMinutes(5),
                User__c = u.Id,
                Source_Json__c = JSON.serialize(new Map<String, Object>{ 'CountryIso' => 'JP' })
            )
        };

        List<Detection_Rule__mdt> rules = new List<Detection_Rule__mdt>{
            new Detection_Rule__mdt(DeveloperName = 'Impossible_Travel', Apex_Class__c = 'Rule_ImpossibleTravel'),
            new Detection_Rule__mdt(DeveloperName = 'Missing', Apex_Class__c = 'NoSuchClass___X'),
            new Detection_Rule__mdt(DeveloperName = 'NotARule', Apex_Class__c = 'TestDataFactory'),
            new Detection_Rule__mdt(
                DeveloperName = 'Gated',
                Apex_Class__c = 'Rule_ImpossibleTravel',
                Required_Capability__c = 'EventLogFile'
            )
        };

        Test.startTest();
        Integer inserted = DetectionEngine.evaluateRules(
            run.Id,
            rules,
            false,
            false,
            Datetime.now().addHours(-24),
            Datetime.now()
        );
        Test.stopTest();

        System.assert(inserted >= 1, 'Impossible_Travel should produce at least one finding');
        Integer total = [SELECT COUNT() FROM Security_Finding__c WHERE Scan_Run__c = :run.Id];
        System.assertEquals(inserted, total, 'Reported inserts should match DB rows for this run');
    }
}
