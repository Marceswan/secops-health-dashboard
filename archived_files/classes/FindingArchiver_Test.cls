@IsTest
private class FindingArchiver_Test {
    @IsTest
    static void archive_removesAgedResolvedFindings() {
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        for (Integer i = 0; i < 3; i++) {
            findings.add(
                new Security_Finding__c(
                    Status__c = 'Remediated',
                    Severity__c = 'High',
                    Category__c = 'Identity',
                    Detection_Rule__c = 'Failed_Login_Burst',
                    Resolved_At__c = Datetime.now().addDays(-100),
                    Action_History__c = 'remediated'
                )
            );
        }
        // One Dismissed finding to confirm the IN-set works.
        findings.add(
            new Security_Finding__c(
                Status__c = 'Dismissed',
                Severity__c = 'Low',
                Category__c = 'OAuth',
                Detection_Rule__c = 'Orphan_ConnectedApp',
                Resolved_At__c = Datetime.now().addDays(-120),
                Action_History__c = 'dismissed'
            )
        );
        // One recent finding that should NOT be archived.
        findings.add(
            new Security_Finding__c(
                Status__c = 'Remediated',
                Severity__c = 'Medium',
                Category__c = 'Identity',
                Detection_Rule__c = 'Failed_Login_Burst',
                Resolved_At__c = Datetime.now().addDays(-1),
                Action_History__c = 'recent'
            )
        );
        insert findings;

        Test.startTest();
        Database.executeBatch(new FindingArchiver(), 200);
        Test.stopTest();

        // The 4 aged rows should be deleted; the recent one should remain.
        Integer remaining = [SELECT COUNT() FROM Security_Finding__c];
        System.assertEquals(1, remaining, 'Only the recent finding should remain after archive');
    }

    @IsTest
    static void archive_emptyScope_noException() {
        Test.startTest();
        Database.executeBatch(new FindingArchiver(), 200);
        Test.stopTest();
        System.assert(true, 'Batch ran without exception against empty scope');
    }
}
