@IsTest
private class Rule_BulkApiFromNewClient_Test {
    @IsTest
    static void evaluate_noEvents_returnsEmpty() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Bulk_Api_From_New_Client');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            true,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_BulkApiFromNewClient().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Should not return null');
        System.assertEquals(0, findings.size(), 'No BulkApi events -> no findings');
    }

    @IsTest
    static void rule_metadata_isApplicableGatedOnEventLogFile() {
        Rule_BulkApiFromNewClient r = new Rule_BulkApiFromNewClient();
        System.assertEquals('Bulk_Api_From_New_Client', r.getDeveloperName());
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        DetectionContext ctxNoCap = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-1),
            Datetime.now(),
            false,
            false,
            null
        );
        System.assertEquals(false, r.isApplicable(ctxNoCap), 'Should not be applicable without EventLogFile');
    }

    @IsTest
    static void evaluate_newClientNoHistory_createsFinding() {
        // A recent BulkApi event with a CLIENT_NAME the user has never used
        // (no historical rows at all) -> finding.
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Bulk_Api_From_New_Client');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            true,
            false,
            cfg
        );
        Id userId = TestDataFactory.standardUser().Id;

        insert new Security_Event__c(
            Event_Type__c = 'BulkApi',
            Event_Time__c = Datetime.now().addHours(-1),
            User__c = userId,
            Source_Json__c = JSON.serialize(new Map<String, Object>{ 'CLIENT_NAME' => 'BrandNewLoader' })
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_BulkApiFromNewClient().evaluate(ctx);
        Test.stopTest();

        System.assertEquals(1, findings.size(), 'New Bulk API client with no history should produce one finding');
        System.assertEquals('OAuth Risk', findings[0].Category__c, 'Category should be OAuth Risk');
        System.assertEquals(SecOpsConstants.SEVERITY_HIGH, findings[0].Severity__c, 'Severity should be High');
        System.assertEquals(userId, findings[0].Subject_User__c, 'Finding should reference the acting user');
    }

    @IsTest
    static void evaluate_knownClient_noFinding() {
        // Recent client matches a historical client (in [30d, 24h) window) -> suppressed.
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Bulk_Api_From_New_Client');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            true,
            false,
            cfg
        );
        Id userId = TestDataFactory.standardUser().Id;

        // Historical row: 5 days ago, same client.
        insert new Security_Event__c(
            Event_Type__c = 'BulkApi',
            Event_Time__c = Datetime.now().addDays(-5),
            User__c = userId,
            Source_Json__c = JSON.serialize(new Map<String, Object>{ 'CLIENT_NAME' => 'EstablishedLoader' })
        );
        // Recent row: same client name -> known.
        insert new Security_Event__c(
            Event_Type__c = 'BulkApi',
            Event_Time__c = Datetime.now().addHours(-1),
            User__c = userId,
            Source_Json__c = JSON.serialize(new Map<String, Object>{ 'CLIENT_NAME' => 'EstablishedLoader' })
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_BulkApiFromNewClient().evaluate(ctx);
        Test.stopTest();

        System.assertEquals(0, findings.size(), 'A previously-seen client should not fire');
    }

    @IsTest
    static void evaluate_blankClientJson_noFinding() {
        // Recent BulkApi event with no client-identifying keys -> client is null
        // -> the rule skips it (covers the null-client branch).
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Bulk_Api_From_New_Client');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            true,
            false,
            cfg
        );
        Id userId = TestDataFactory.standardUser().Id;

        insert new Security_Event__c(
            Event_Type__c = 'BulkApi',
            Event_Time__c = Datetime.now().addHours(-1),
            User__c = userId,
            Source_Json__c = JSON.serialize(new Map<String, Object>{ 'UNRELATED_KEY' => 'x' })
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_BulkApiFromNewClient().evaluate(ctx);
        Test.stopTest();

        System.assertEquals(0, findings.size(), 'Event with no extractable client should not fire');
    }
}
