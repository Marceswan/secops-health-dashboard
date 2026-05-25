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
}
