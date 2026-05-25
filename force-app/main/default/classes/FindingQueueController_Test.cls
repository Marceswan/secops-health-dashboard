@IsTest
private class FindingQueueController_Test {
    @IsTest
    static void getOpenFindings_returnsNonNullList() {
        Test.startTest();
        List<FindingQueueController.FindingRow> rows = FindingQueueController.getOpenFindings(null);
        Test.stopTest();

        System.assertNotEquals(null, rows, 'Controller should never return null');
    }

    @IsTest
    static void getOpenFindings_respectsLimit() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        // Insert a couple of open findings so the controller has rows to project.
        Security_Finding__c f1 = FindingFactory.build(
            run.Id,
            'Unit_Test_Rule',
            'Login Anomaly',
            SecOpsConstants.SEVERITY_HIGH,
            null,
            null,
            'evt-1',
            new Map<String, Object>{ 'k' => 1 }
        );
        Security_Finding__c f2 = FindingFactory.build(
            run.Id,
            'Unit_Test_Rule',
            'Login Anomaly',
            SecOpsConstants.SEVERITY_MEDIUM,
            null,
            null,
            'evt-2',
            new Map<String, Object>{ 'k' => 2 }
        );
        insert new List<Security_Finding__c>{ f1, f2 };

        List<FindingQueueController.FindingRow> rows = FindingQueueController.getOpenFindings(1);
        System.assertEquals(1, rows.size(), 'Explicit limit should cap results');
    }

    @IsTest
    static void getCriticalCount_countsOnlyNewCritical() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Security_Finding__c critical = FindingFactory.build(
            run.Id,
            'Unit_Test_Rule',
            'Login Anomaly',
            SecOpsConstants.SEVERITY_CRITICAL,
            null,
            null,
            'evt-c',
            new Map<String, Object>{ 'k' => 1 }
        );
        Security_Finding__c high = FindingFactory.build(
            run.Id,
            'Unit_Test_Rule',
            'Login Anomaly',
            SecOpsConstants.SEVERITY_HIGH,
            null,
            null,
            'evt-h',
            new Map<String, Object>{ 'k' => 2 }
        );
        insert new List<Security_Finding__c>{ critical, high };

        Test.startTest();
        Integer count = FindingQueueController.getCriticalCount();
        Test.stopTest();

        System.assertEquals(1, count, 'Only New + Critical should be counted');
    }
}
