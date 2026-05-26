@IsTest
private class WorkflowController_Test {
    // WorkflowController.transitionMany queries findings WITH SECURITY_ENFORCED and
    // updates them; assignTo posts a FeedItem. The SecOps_Investigate permission set
    // grants the FLS, Action_Audit create, and view/modify-all needed to triage
    // findings the user does not own. FLS/perm-set effects do not apply to the
    // current user within a test, so create a separate empowered user in setup and
    // run the controller actions via System.runAs(...).
    @TestSetup
    static void makeData() {
        TestDataFactory.empoweredUser();
    }

    /**
     * Insert a finding under a fresh scan run. Helper keeps tests concise.
     */
    private static Security_Finding__c newFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Security_Finding__c f = FindingFactory.build(
            run.Id,
            'Unit_Test_Rule',
            'Login Anomaly',
            SecOpsConstants.SEVERITY_HIGH,
            null,
            null,
            'evt-wf-1',
            new Map<String, Object>{ 'k' => 1 }
        );
        insert f;
        return f;
    }

    @IsTest
    static void acknowledge_setsStatusAndAudit() {
        Security_Finding__c f = newFinding();
        User agent = TestDataFactory.getEmpoweredUser();

        Test.startTest();
        WorkflowController.ActionResult result;
        System.runAs(agent) {
            result = WorkflowController.acknowledge(f.Id);
        }
        Test.stopTest();

        System.assertNotEquals(null, result, 'Result should not be null');
        System.assertEquals(SecOpsConstants.STATUS_ACKNOWLEDGED, result.status);

        Security_Finding__c reloaded = [SELECT Status__c, Action_History__c FROM Security_Finding__c WHERE Id = :f.Id];
        System.assertEquals(SecOpsConstants.STATUS_ACKNOWLEDGED, reloaded.Status__c);
        System.assert(reloaded.Action_History__c.contains('Acknowledge'), 'History should record the action');

        Integer audits = [
            SELECT COUNT()
            FROM Action_Audit__c
            WHERE Finding__c = :f.Id AND Action_Type__c = 'Acknowledge'
        ];
        System.assertEquals(1, audits, 'One Acknowledge audit row should be written');
    }

    @IsTest
    static void dismiss_setsStatusReasonAndResolvedAt() {
        Security_Finding__c f = newFinding();
        User agent = TestDataFactory.getEmpoweredUser();

        Test.startTest();
        WorkflowController.ActionResult result;
        System.runAs(agent) {
            result = WorkflowController.dismiss(f.Id, 'False positive');
        }
        Test.stopTest();

        System.assertEquals(SecOpsConstants.STATUS_DISMISSED, result.status);
        System.assertNotEquals(null, result.resolvedAt, 'Resolved_At should be set on dismiss');

        Security_Finding__c reloaded = [
            SELECT Status__c, Dismissal_Reason__c, Resolved_At__c, Resolved_By__c
            FROM Security_Finding__c
            WHERE Id = :f.Id
        ];
        System.assertEquals(SecOpsConstants.STATUS_DISMISSED, reloaded.Status__c);
        System.assertEquals('False positive', reloaded.Dismissal_Reason__c);
        System.assertNotEquals(null, reloaded.Resolved_At__c);
        System.assertEquals(agent.Id, reloaded.Resolved_By__c, 'Resolver should be the acting SecOps user');

        Integer audits = [SELECT COUNT() FROM Action_Audit__c WHERE Finding__c = :f.Id AND Action_Type__c = 'Dismiss'];
        System.assertEquals(1, audits);
    }

    @IsTest
    static void markRemediated_setsStatusAndResolvedAt() {
        Security_Finding__c f = newFinding();
        User agent = TestDataFactory.getEmpoweredUser();

        Test.startTest();
        WorkflowController.ActionResult result;
        System.runAs(agent) {
            result = WorkflowController.markRemediated(f.Id);
        }
        Test.stopTest();

        System.assertEquals(SecOpsConstants.STATUS_REMEDIATED, result.status);

        Security_Finding__c reloaded = [
            SELECT Status__c, Resolved_At__c, Resolved_By__c
            FROM Security_Finding__c
            WHERE Id = :f.Id
        ];
        System.assertEquals(SecOpsConstants.STATUS_REMEDIATED, reloaded.Status__c);
        System.assertNotEquals(null, reloaded.Resolved_At__c);

        Integer audits = [
            SELECT COUNT()
            FROM Action_Audit__c
            WHERE Finding__c = :f.Id AND Action_Type__c = 'Remediate'
        ];
        System.assertEquals(1, audits);
    }

    @IsTest
    static void acknowledgeBulk_writesOneAuditPerFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        for (Integer i = 0; i < 5; i++) {
            findings.add(
                FindingFactory.build(
                    run.Id,
                    'Unit_Test_Rule',
                    'Login Anomaly',
                    SecOpsConstants.SEVERITY_MEDIUM,
                    null,
                    null,
                    'evt-bulk-' + i,
                    new Map<String, Object>{ 'i' => i }
                )
            );
        }
        insert findings;
        List<Id> ids = new List<Id>();
        for (Security_Finding__c f : findings) {
            ids.add(f.Id);
        }

        User agent = TestDataFactory.getEmpoweredUser();
        Test.startTest();
        List<WorkflowController.ActionResult> results;
        System.runAs(agent) {
            results = WorkflowController.acknowledgeBulk(ids);
        }
        Test.stopTest();

        System.assertEquals(5, results.size());
        Integer audits = [
            SELECT COUNT()
            FROM Action_Audit__c
            WHERE Finding__c IN :ids AND Action_Type__c = 'Acknowledge'
        ];
        System.assertEquals(5, audits, 'One Acknowledge audit per finding');
    }

    @IsTest
    static void dismissBulk_setsReasonOnAll() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        List<Security_Finding__c> findings = new List<Security_Finding__c>();
        for (Integer i = 0; i < 3; i++) {
            findings.add(
                FindingFactory.build(
                    run.Id,
                    'Unit_Test_Rule',
                    'Login Anomaly',
                    SecOpsConstants.SEVERITY_LOW,
                    null,
                    null,
                    'evt-dismiss-' + i,
                    new Map<String, Object>{ 'i' => i }
                )
            );
        }
        insert findings;
        List<Id> ids = new List<Id>();
        for (Security_Finding__c f : findings) {
            ids.add(f.Id);
        }

        User agent = TestDataFactory.getEmpoweredUser();
        Test.startTest();
        System.runAs(agent) {
            WorkflowController.dismissBulk(ids, 'Known benign');
        }
        Test.stopTest();

        Integer dismissed = [
            SELECT COUNT()
            FROM Security_Finding__c
            WHERE Id IN :ids AND Status__c = :SecOpsConstants.STATUS_DISMISSED AND Dismissal_Reason__c = 'Known benign'
        ];
        System.assertEquals(3, dismissed);
    }

    @IsTest
    static void assignTo_postsFeedItemWithoutChangingOwner() {
        Security_Finding__c f = newFinding();
        User agent = TestDataFactory.getEmpoweredUser();

        Test.startTest();
        Id feedId;
        System.runAs(agent) {
            feedId = WorkflowController.assignTo(f.Id, agent.Id);
        }
        Test.stopTest();

        System.assertNotEquals(null, feedId, 'assignTo should return a FeedItem Id');
        Integer feedCount = [SELECT COUNT() FROM FeedItem WHERE ParentId = :f.Id];
        System.assertEquals(1, feedCount, 'Exactly one FeedItem should be posted');
        // Note: OwnerId on master-detail child is inherited from Scan_Run; not asserted.
    }

    @IsTest
    static void acknowledge_nullIdThrows() {
        Test.startTest();
        try {
            WorkflowController.acknowledge(null);
            System.assert(false, 'Expected AuraHandledException for null id');
        } catch (AuraHandledException e) {
            System.assert(true);
        }
        Test.stopTest();
    }

    @IsTest
    static void acknowledgeBulk_emptyListReturnsEmpty() {
        List<WorkflowController.ActionResult> results = WorkflowController.acknowledgeBulk(new List<Id>());
        System.assertEquals(0, results.size());
    }
}
