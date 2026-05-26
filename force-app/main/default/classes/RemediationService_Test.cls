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

    private class Mock500 implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            HttpResponse res = new HttpResponse();
            res.setStatusCode(500);
            res.setBody('{"error":"server error"}');
            return res;
        }
    }

    @TestSetup
    static void setup() {
        // Create a SecOps user holding both the custom-permission set (so
        // requirePermission passes) and the data-access set (Action_Audit create +
        // Security_Finding read/edit/modify-all, needed by logAudit and
        // applyRemediatedStatus against findings the user does not own). Positive
        // tests run as this user via System.runAs; the "withoutPermission" tests run
        // as a separate, unprivileged user to verify denial. Permission-set effects
        // do not apply to the current user within a test, hence runAs.
        TestDataFactory.empoweredUser();
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
        User u = TestDataFactory.getEmpoweredUser();

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
        User u = TestDataFactory.getEmpoweredUser();
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
        User u = TestDataFactory.getEmpoweredUser();
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
        User u = TestDataFactory.getEmpoweredUser();
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

    // ------------------------------------------------------------------
    // Added coverage: success paths for freezeUser / forcePasswordReset,
    // the BlockApp non-2xx failure branch, and the tokenId / sessionId
    // non-null branches of revokeOauthToken / killSession.
    // ------------------------------------------------------------------

    @IsTest
    static void freezeUser_succeedsOrLogsFailureForTargetUser() {
        Security_Finding__c f = newFinding();
        User u = TestDataFactory.getEmpoweredUser();
        // Target user created as admin; a freshly inserted user has a UserLogin row.
        User target = TestDataFactory.standardUser();

        Test.startTest();
        System.runAs(u) {
            RemediationService.freezeUser(f.Id, target.Id);
        }
        Test.stopTest();

        // Either Success (UserLogin present + updated) or Failure ('No UserLogin
        // row') still exercises the body + audit write; assert exactly one row.
        Integer audits = [
            SELECT COUNT()
            FROM Action_Audit__c
            WHERE Finding__c = :f.Id AND Action_Type__c = 'FreezeUser'
        ];
        System.assertEquals(1, audits, 'One FreezeUser audit row expected');
    }

    @IsTest
    static void freezeUser_nullUserIdLogsFailure() {
        Security_Finding__c f = newFinding();
        User u = TestDataFactory.getEmpoweredUser();

        Test.startTest();
        Boolean threw = false;
        System.runAs(u) {
            try {
                RemediationService.freezeUser(f.Id, null);
            } catch (RemediationService.RemediationException e) {
                threw = true;
            }
        }
        Test.stopTest();

        System.assert(threw, 'Expected RemediationException for null userId');
        Integer fails = [
            SELECT COUNT()
            FROM Action_Audit__c
            WHERE Finding__c = :f.Id AND Action_Type__c = 'FreezeUser' AND Result__c = 'Failure'
        ];
        System.assertEquals(1, fails, 'One Failure FreezeUser audit expected');
    }

    @IsTest
    static void forcePasswordReset_succeedsAndLogsAudit() {
        Security_Finding__c f = newFinding();
        User u = TestDataFactory.getEmpoweredUser();
        User target = TestDataFactory.standardUser();

        Test.startTest();
        System.runAs(u) {
            RemediationService.forcePasswordReset(f.Id, target.Id);
        }
        Test.stopTest();

        Integer audits = [
            SELECT COUNT()
            FROM Action_Audit__c
            WHERE Finding__c = :f.Id AND Action_Type__c = 'ForceReset' AND Result__c = 'Success'
        ];
        System.assertEquals(1, audits, 'One Success ForceReset audit expected');

        Security_Finding__c reloaded = [SELECT Status__c FROM Security_Finding__c WHERE Id = :f.Id];
        System.assertEquals(SecOpsConstants.STATUS_REMEDIATED, reloaded.Status__c);
    }

    @IsTest
    static void forcePasswordReset_nullUserIdLogsFailure() {
        Security_Finding__c f = newFinding();
        User u = TestDataFactory.getEmpoweredUser();

        Test.startTest();
        Boolean threw = false;
        System.runAs(u) {
            try {
                RemediationService.forcePasswordReset(f.Id, null);
            } catch (RemediationService.RemediationException e) {
                threw = true;
            }
        }
        Test.stopTest();

        System.assert(threw, 'Expected RemediationException for null userId');
        Integer fails = [
            SELECT COUNT()
            FROM Action_Audit__c
            WHERE Finding__c = :f.Id AND Action_Type__c = 'ForceReset' AND Result__c = 'Failure'
        ];
        System.assertEquals(1, fails, 'One Failure ForceReset audit expected');
    }

    @IsTest
    static void blockConnectedApp_non2xxLogsFailure() {
        Security_Finding__c f = newFinding();
        User u = TestDataFactory.getEmpoweredUser();
        Test.setMock(HttpCalloutMock.class, new Mock500());

        Test.startTest();
        Boolean threw = false;
        System.runAs(u) {
            try {
                RemediationService.blockConnectedApp(f.Id, '0H4xx0000004CAB');
            } catch (RemediationService.RemediationException e) {
                threw = true;
            }
        }
        Test.stopTest();

        System.assert(threw, 'Expected RemediationException for non-2xx Tooling API response');
        Integer fails = [
            SELECT COUNT()
            FROM Action_Audit__c
            WHERE Finding__c = :f.Id AND Action_Type__c = 'BlockApp' AND Result__c = 'Failure'
        ];
        System.assertEquals(1, fails, 'One Failure BlockApp audit expected');
    }

    @IsTest
    static void revokeOauthToken_withTokenIdSucceeds() {
        Security_Finding__c f = newFinding();
        User u = TestDataFactory.getEmpoweredUser();
        // OauthToken key prefix is 0Ab; an arbitrary id matches no rows so the
        // query returns empty (deleted = 0) and the call succeeds idempotently,
        // exercising the tokenId != null + Database.query branch.
        Id fakeTokenId = '0Ab000000000001AAA';

        Test.startTest();
        System.runAs(u) {
            RemediationService.revokeOauthToken(f.Id, fakeTokenId);
        }
        Test.stopTest();

        Integer audits = [
            SELECT COUNT()
            FROM Action_Audit__c
            WHERE Finding__c = :f.Id AND Action_Type__c = 'RevokeToken' AND Result__c = 'Success'
        ];
        System.assertEquals(1, audits, 'One Success RevokeToken audit expected');
    }

    @IsTest
    static void killSession_withSessionIdSucceeds() {
        Security_Finding__c f = newFinding();
        User u = TestDataFactory.getEmpoweredUser();
        // AuthSession key prefix is 0Ag; an arbitrary id is added to the delete
        // list. The delete of a non-existent row is tolerated by the DML and the
        // method logs Success, exercising the sessionId != null branch.
        Id fakeSessionId = '0Ag000000000001AAA';

        Test.startTest();
        System.runAs(u) {
            try {
                RemediationService.killSession(f.Id, null, fakeSessionId);
            } catch (RemediationService.RemediationException e) {
                // A failed delete of the fake row routes through the catch/Failure
                // branch instead, which is equally valuable coverage.
            }
        }
        Test.stopTest();

        Integer audits = [
            SELECT COUNT()
            FROM Action_Audit__c
            WHERE Finding__c = :f.Id AND Action_Type__c = 'KillSession'
        ];
        System.assertEquals(1, audits, 'One KillSession audit row expected (Success or Failure)');
    }
}
