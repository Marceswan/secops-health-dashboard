@IsTest
private class RemediationService_Test {
    private class PatchMock204 implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            HttpResponse res = new HttpResponse();
            res.setStatusCode(204);
            res.setBody('');
            return res;
        }
    }

    @TestSetup
    static void setup() {
        // Create a test user and assign the SecOps_Destructive_Remediation permission set.
        User u = TestDataFactory.standardUser();
        PermissionSet ps = [
            SELECT Id
            FROM PermissionSet
            WHERE Name = 'SecOps_Destructive_Remediation'
            LIMIT 1
        ];
        insert new PermissionSetAssignment(AssigneeId = u.Id, PermissionSetId = ps.Id);
    }

    private static User getEmpoweredUser() {
        PermissionSet ps = [
            SELECT Id
            FROM PermissionSet
            WHERE Name = 'SecOps_Destructive_Remediation'
            LIMIT 1
        ];
        return [
            SELECT Id
            FROM User
            WHERE
                Id IN (SELECT AssigneeId FROM PermissionSetAssignment WHERE PermissionSetId = :ps.Id)
                AND IsActive = TRUE
            LIMIT 1
        ];
    }

    /**
     * Build a finding under a fresh scan run for the test to operate on.
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
            'evt-remediation-' + Crypto.getRandomInteger(),
            new Map<String, Object>{ 'k' => 1 }
        );
        insert f;
        return f;
    }

    @IsTest
    static void revokeOauthToken_succeedsAndLogsAudit() {
        Security_Finding__c f = newFinding();
        User u = getEmpoweredUser();

        Test.startTest();
        System.runAs(u) {
            RemediationService.revokeOauthToken(f.Id, null);
        }
        Test.stopTest();

        Integer audits = [
            SELECT COUNT()
            FROM Action_Audit__c
            WHERE Finding__c = :f.Id AND Action_Type__c = 'RevokeToken' AND Result__c = 'Success'
        ];
        System.assertEquals(1, audits, 'One success audit row expected');

        Security_Finding__c reloaded = [SELECT Status__c FROM Security_Finding__c WHERE Id = :f.Id];
        System.assertEquals(SecOpsConstants.STATUS_REMEDIATED, reloaded.Status__c);
    }

    @IsTest
    static void killSession_handlesNoSessionsGracefully() {
        Security_Finding__c f = newFinding();
        User u = getEmpoweredUser();
        Id fakeUser = UserInfo.getUserId();

        Test.startTest();
        System.runAs(u) {
            RemediationService.killSession(f.Id, fakeUser, null);
        }
        Test.stopTest();

        Integer audits = [
            SELECT COUNT()
            FROM Action_Audit__c
            WHERE Finding__c = :f.Id AND Action_Type__c = 'KillSession'
        ];
        System.assertEquals(1, audits, 'One KillSession audit row expected');
    }

    @IsTest
    static void blockConnectedApp_204isSuccess() {
        Security_Finding__c f = newFinding();
        User u = getEmpoweredUser();
        Test.setMock(HttpCalloutMock.class, new PatchMock204());

        Test.startTest();
        System.runAs(u) {
            RemediationService.blockConnectedApp(f.Id, '0H4xx0000004CAB');
        }
        Test.stopTest();

        Integer audits = [
            SELECT COUNT()
            FROM Action_Audit__c
            WHERE Finding__c = :f.Id AND Action_Type__c = 'BlockApp' AND Result__c = 'Success'
        ];
        System.assertEquals(1, audits, 'One Success BlockApp audit expected');

        Security_Finding__c reloaded = [SELECT Status__c FROM Security_Finding__c WHERE Id = :f.Id];
        System.assertEquals(SecOpsConstants.STATUS_REMEDIATED, reloaded.Status__c);
    }

    @IsTest
    static void blockConnectedApp_blankAppIdLogsFailure() {
        Security_Finding__c f = newFinding();
        User u = getEmpoweredUser();
        Test.setMock(HttpCalloutMock.class, new PatchMock204());

        Test.startTest();
        Boolean threw = false;
        System.runAs(u) {
            try {
                RemediationService.blockConnectedApp(f.Id, null);
            } catch (RemediationService.RemediationException e) {
                threw = true;
            }
        }
        Test.stopTest();

        System.assert(threw, 'Expected RemediationException for blank connectedAppId');
        Integer fails = [
            SELECT COUNT()
            FROM Action_Audit__c
            WHERE Finding__c = :f.Id AND Action_Type__c = 'BlockApp' AND Result__c = 'Failure'
        ];
        System.assertEquals(1, fails);
    }

    @IsTest
    static void freezeUser_withoutPermissionThrows() {
        Security_Finding__c f = newFinding();
        // Create a user WITHOUT the permission set assigned.
        User noPerm = TestDataFactory.standardUser();

        Test.startTest();
        Boolean threw = false;
        System.runAs(noPerm) {
            try {
                RemediationService.freezeUser(f.Id, noPerm.Id);
            } catch (RemediationService.RemediationException e) {
                threw = true;
            }
        }
        Test.stopTest();

        System.assert(threw, 'Expected RemediationException due to missing permission');
    }

    @IsTest
    static void forcePasswordReset_withoutPermissionThrows() {
        Security_Finding__c f = newFinding();
        User noPerm = TestDataFactory.standardUser();

        Test.startTest();
        Boolean threw = false;
        System.runAs(noPerm) {
            try {
                RemediationService.forcePasswordReset(f.Id, noPerm.Id);
            } catch (RemediationService.RemediationException e) {
                threw = true;
            }
        }
        Test.stopTest();

        System.assert(threw, 'Expected RemediationException due to missing permission');
    }

    @IsTest
    static void revokeOauthToken_withoutPermissionThrows() {
        Security_Finding__c f = newFinding();
        User noPerm = TestDataFactory.standardUser();

        Test.startTest();
        Boolean threw = false;
        System.runAs(noPerm) {
            try {
                RemediationService.revokeOauthToken(f.Id, null);
            } catch (RemediationService.RemediationException e) {
                threw = true;
            }
        }
        Test.stopTest();

        System.assert(threw, 'Expected RemediationException due to missing permission');
    }
}
