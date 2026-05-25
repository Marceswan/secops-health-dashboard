@IsTest
private class InvestigateController_Test {
    @IsTest
    static void listActiveUsers_returnsAtLeastCurrentUser() {
        Test.startTest();
        List<User> users = InvestigateController.listActiveUsers(null);
        Test.stopTest();

        System.assertNotEquals(null, users, 'Should never return null');
        System.assert(!users.isEmpty(), 'At least the running user should be active');
    }

    @IsTest
    static void getTimelineForUser_includesFindingRow() {
        User u = TestDataFactory.standardUser();
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Security_Finding__c f = FindingFactory.build(
            run.Id,
            'Unit_Test_Rule',
            'Login Anomaly',
            SecOpsConstants.SEVERITY_HIGH,
            u.Id,
            null,
            'evt-tl-1',
            new Map<String, Object>{ 'countryIso' => 'CN' }
        );
        insert f;

        Test.startTest();
        List<InvestigateController.TimelineEntry> entries = InvestigateController.getTimelineForUser(u.Id, 30);
        Test.stopTest();

        System.assertNotEquals(null, entries, 'Should return a list (possibly empty)');
        Boolean foundFinding = false;
        for (InvestigateController.TimelineEntry e : entries) {
            if ('Finding'.equals(e.entryType) && e.refId == f.Id) {
                foundFinding = true;
                break;
            }
        }
        System.assert(foundFinding, 'Inserted finding should appear in the timeline');
    }

    @IsTest
    static void getTimelineForUser_returnsEmptyForNullUser() {
        List<InvestigateController.TimelineEntry> entries = InvestigateController.getTimelineForUser(null, 30);
        System.assertNotEquals(null, entries, 'Null user yields empty list, not null');
        System.assertEquals(0, entries.size(), 'Null user should yield zero rows');
    }

    @IsTest
    static void getCrossUserHeatmap_returnsListShape() {
        User u = TestDataFactory.standardUser();
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Security_Finding__c f = FindingFactory.build(
            run.Id,
            'Unit_Test_Rule',
            'Login Anomaly',
            SecOpsConstants.SEVERITY_MEDIUM,
            u.Id,
            null,
            'evt-hm-1',
            new Map<String, Object>{ 'k' => 'v' }
        );
        insert f;

        Test.startTest();
        List<Map<String, Object>> rows = InvestigateController.getCrossUserHeatmap(30);
        Test.stopTest();

        System.assertNotEquals(null, rows, 'Heatmap should never return null');
    }

    @IsTest
    static void diffAgainstBaseline_flagsForeignCountry() {
        User u = TestDataFactory.standardUser();
        User_Baseline__c b = new User_Baseline__c(
            User__c = u.Id,
            User_Id_External__c = u.Id,
            Country_Set__c = 'US',
            Ip24_Set__c = '10.20.30.0/24',
            App_Set__c = 'Salesforce for Outlook',
            Browser_Set__c = 'Chrome',
            Hour_Histogram__c = JSON.serialize(
                new List<Integer>{
                    10,
                    10,
                    10,
                    10,
                    10,
                    10,
                    10,
                    10,
                    10,
                    10,
                    10,
                    10,
                    10,
                    10,
                    10,
                    10,
                    10,
                    10,
                    10,
                    10,
                    10,
                    10,
                    10,
                    10
                }
            ),
            Sample_Size__c = 240,
            Last_Refreshed__c = Datetime.now()
        );
        insert b;

        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Security_Finding__c f = FindingFactory.build(
            run.Id,
            'Unit_Test_Rule',
            'Login Anomaly',
            SecOpsConstants.SEVERITY_HIGH,
            u.Id,
            null,
            'evt-diff-1',
            new Map<String, Object>{ 'countryIso' => 'CN', 'sourceIp' => '99.99.99.10', 'application' => 'Unknown App' }
        );
        insert f;

        Test.startTest();
        List<String> diff = InvestigateController.diffAgainstBaseline(f.Id);
        Test.stopTest();

        System.assertNotEquals(null, diff, 'Diff should never return null');
        System.assert(diff.contains('countryIso'), 'CN should diverge from US-only baseline');
    }

    @IsTest
    static void diffAgainstBaseline_returnsEmptyForNullId() {
        List<String> diff = InvestigateController.diffAgainstBaseline(null);
        System.assertNotEquals(null, diff);
        System.assertEquals(0, diff.size(), 'Null id yields empty diff');
    }

    @IsTest
    static void timelineEntry_compareTo_sortsDescending() {
        InvestigateController.TimelineEntry a = new InvestigateController.TimelineEntry();
        a.ts = Datetime.newInstance(2026, 1, 1);
        InvestigateController.TimelineEntry b = new InvestigateController.TimelineEntry();
        b.ts = Datetime.newInstance(2026, 6, 1);

        List<InvestigateController.TimelineEntry> list1 = new List<InvestigateController.TimelineEntry>{ a, b };
        list1.sort();

        System.assertEquals(b.ts, list1[0].ts, 'Newer timestamp should sort first');
        System.assertEquals(a.ts, list1[1].ts, 'Older timestamp should sort last');
    }
}
