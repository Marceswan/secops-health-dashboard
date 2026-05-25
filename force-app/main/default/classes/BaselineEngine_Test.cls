@IsTest
private class BaselineEngine_Test {
    @IsTest
    static void buildAndLookup_persistsAndReadsBaseline() {
        User u = TestDataFactory.standardUser();

        Test.startTest();
        User_Baseline__c b = BaselineEngine.buildForUser(u.Id, Datetime.now().addDays(-90));
        insert b;
        User_Baseline__c found = BaselineEngine.getBaselineFor(u.Id);
        Test.stopTest();

        System.assertNotEquals(null, found, 'getBaselineFor should return the inserted baseline');
        System.assertEquals(u.Id, found.User__c, 'Baseline should point at the test user');
        System.assertEquals(String.valueOf(u.Id), found.User_Id_External__c, 'External id should mirror User__c');
    }

    @IsTest
    static void getBaselineFor_nullAndMissing_returnsNull() {
        System.assertEquals(null, BaselineEngine.getBaselineFor(null), 'Null user id returns null');
        User u = TestDataFactory.standardUser();
        System.assertEquals(null, BaselineEngine.getBaselineFor(u.Id), 'No baseline yet -> null');
    }

    @IsTest
    static void isCountryInBaseline_membershipChecks() {
        User_Baseline__c b = new User_Baseline__c(
            Country_Set__c = 'US\nCA\nGB',
            Sample_Size__c = 50,
            Last_Refreshed__c = Datetime.now()
        );
        System.assert(BaselineEngine.isCountryInBaseline(b, 'US'), 'US is in baseline');
        System.assert(BaselineEngine.isCountryInBaseline(b, 'CA'), 'CA is in baseline');
        System.assert(!BaselineEngine.isCountryInBaseline(b, 'RU'), 'RU is not in baseline');
        System.assert(!BaselineEngine.isCountryInBaseline(null, 'US'), 'Null baseline -> false');
        System.assert(!BaselineEngine.isCountryInBaseline(b, null), 'Null country -> false');
    }

    @IsTest
    static void isWarmedUp_thresholdChecks() {
        User_Baseline__c cold = new User_Baseline__c(Sample_Size__c = 5);
        User_Baseline__c hot = new User_Baseline__c(Sample_Size__c = SecOpsConstants.BASELINE_WARMUP_THRESHOLD);
        System.assert(!BaselineEngine.isWarmedUp(cold), 'Sample below threshold -> cold');
        System.assert(BaselineEngine.isWarmedUp(hot), 'Sample at threshold -> warmed up');
        System.assert(!BaselineEngine.isWarmedUp(null), 'Null baseline -> cold');
    }

    @IsTest
    static void isHourAnomalous_lowVsHighFrequency() {
        // Construct a 24-bucket histogram with hour 9 = 50, hour 3 = 1, rest = 49 spread
        Integer[] hist = new Integer[24];
        for (Integer i = 0; i < 24; i++) {
            hist[i] = 0;
        }
        hist[9] = 50; // dominant working hour
        hist[3] = 1; // rare early-morning
        // Pad so total > BASELINE_WARMUP_THRESHOLD and percentages remain telling
        for (Integer i = 10; i < 18; i++) {
            hist[i] = 6;
        }
        Integer total = 0;
        for (Integer i = 0; i < 24; i++) {
            total += hist[i];
        }

        User_Baseline__c b = new User_Baseline__c(
            Sample_Size__c = total,
            Hour_Histogram__c = JSON.serialize(hist),
            Last_Refreshed__c = Datetime.now()
        );

        System.assert(!BaselineEngine.isHourAnomalous(b, 9), 'Hour 9 is the dominant hour -> not anomalous');
        System.assert(BaselineEngine.isHourAnomalous(b, 3), 'Hour 3 is < 2% of logins -> anomalous');
        System.assert(!BaselineEngine.isHourAnomalous(null, 9), 'Null baseline -> not anomalous');
    }

    @IsTest
    static void toIp24_parsesValidIpv4AndRejectsInvalid() {
        System.assertEquals('10.20.30.0/24', BaselineEngine.toIp24('10.20.30.45'));
        System.assertEquals(null, BaselineEngine.toIp24(null));
        System.assertEquals(null, BaselineEngine.toIp24('not.an.ip'));
        System.assertEquals(null, BaselineEngine.toIp24('::1'));
    }

    @IsTest
    static void loadBaselines_bulkLookup() {
        User u = TestDataFactory.standardUser();
        User_Baseline__c b = BaselineEngine.buildForUser(u.Id, Datetime.now().addDays(-30));
        insert b;
        Map<Id, User_Baseline__c> byUser = BaselineEngine.loadBaselines(new Set<Id>{ u.Id });
        System.assertEquals(1, byUser.size(), 'Should load one baseline');
        System.assert(byUser.containsKey(u.Id), 'Map keyed by user id');
    }

    @IsTest
    static void getHealthStats_returnsExpectedKeys() {
        User u = TestDataFactory.standardUser();
        User_Baseline__c b = BaselineEngine.buildForUser(u.Id, Datetime.now().addDays(-30));
        insert b;

        Test.startTest();
        Map<String, Object> stats = BaselineEngine.getHealthStats();
        Test.stopTest();

        System.assertNotEquals(null, stats, 'getHealthStats should return a map');
        System.assert(stats.containsKey('totalUsers'), 'stats has totalUsers');
        System.assert(stats.containsKey('usersWithBaseline'), 'stats has usersWithBaseline');
        System.assert(stats.containsKey('usersWithoutBaseline'), 'stats has usersWithoutBaseline');
        System.assert(stats.containsKey('oldestRefresh'), 'stats has oldestRefresh');
        System.assert(stats.containsKey('newestRefresh'), 'stats has newestRefresh');
        System.assert(((Integer) stats.get('usersWithBaseline')) >= 1, 'At least one baseline present');
    }

    @IsTest
    static void refreshAllNow_enqueuesQueueable() {
        Test.startTest();
        BaselineEngine.refreshAllNow();
        Test.stopTest();
        // Test.stopTest completes any enqueued jobs; no exception is the assertion.
        System.assert(true, 'refreshAllNow enqueued without exception');
    }
}
