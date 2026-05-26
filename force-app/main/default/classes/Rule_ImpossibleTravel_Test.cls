@IsTest
private class Rule_ImpossibleTravel_Test {
    @IsTest
    static void roughDistance_knownCountries_returnsPositive() {
        Double d = LoginGeoLookup.roughDistance('US', 'JP');
        System.assertNotEquals(null, d, 'Both countries are known');
        System.assert(d > 5000, 'US to JP should be more than 5000 km');
    }

    @IsTest
    static void roughDistance_sameCountry_returnsZero() {
        System.assertEquals(0, LoginGeoLookup.roughDistance('US', 'US'));
    }

    @IsTest
    static void roughDistance_unknownCountry_returnsNull() {
        System.assertEquals(null, LoginGeoLookup.roughDistance('ZZ', 'US'));
    }

    @IsTest
    static void evaluate_noData_returnsEmptyList() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Impossible_Travel');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_ImpossibleTravel().evaluate(ctx);
        Test.stopTest();

        System.assertEquals(0, findings.size(), 'No login events should produce no findings');
    }

    @IsTest
    static void developerName_isStable() {
        System.assertEquals('Impossible_Travel', new Rule_ImpossibleTravel().getDeveloperName());
    }

    @IsTest
    static void evaluate_usToJpInFiveMinutes_createsFinding() {
        // US->JP is >5000 km (asserted above). Two logins 5 minutes apart imply
        // a speed of ~60000+ km/h, far above the 900 km/h threshold -> finding.
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Impossible_Travel');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );
        Id userId = TestDataFactory.standardUser().Id;

        insert new Security_Event__c(
            Event_Type__c = 'LoginHistory',
            Event_Time__c = Datetime.now().addMinutes(-65),
            User__c = userId,
            Source_Json__c = JSON.serialize(new Map<String, Object>{ 'CountryIso' => 'US' })
        );
        insert new Security_Event__c(
            Event_Type__c = 'LoginHistory',
            Event_Time__c = Datetime.now().addMinutes(-60),
            User__c = userId,
            Source_Json__c = JSON.serialize(new Map<String, Object>{ 'CountryIso' => 'JP' })
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_ImpossibleTravel().evaluate(ctx);
        Test.stopTest();

        System.assertEquals(1, findings.size(), 'US->JP in 5 minutes should produce one finding');
        System.assertEquals('Login Anomaly', findings[0].Category__c, 'Category should be Login Anomaly');
        System.assertEquals(SecOpsConstants.SEVERITY_CRITICAL, findings[0].Severity__c, 'Severity should be Critical');
        System.assertEquals(userId, findings[0].Subject_User__c, 'Finding should reference the traveling user');
    }

    @IsTest
    static void evaluate_sameCountry_noFinding() {
        // Two US logins 5 minutes apart -> distance 0 -> rule skips (no finding).
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Impossible_Travel');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );
        Id userId = TestDataFactory.standardUser().Id;

        insert new Security_Event__c(
            Event_Type__c = 'LoginHistory',
            Event_Time__c = Datetime.now().addMinutes(-65),
            User__c = userId,
            Source_Json__c = JSON.serialize(new Map<String, Object>{ 'CountryIso' => 'US' })
        );
        insert new Security_Event__c(
            Event_Type__c = 'LoginHistory',
            Event_Time__c = Datetime.now().addMinutes(-60),
            User__c = userId,
            Source_Json__c = JSON.serialize(new Map<String, Object>{ 'CountryIso' => 'US' })
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_ImpossibleTravel().evaluate(ctx);
        Test.stopTest();

        System.assertEquals(0, findings.size(), 'Same-country logins should not fire');
    }
}
