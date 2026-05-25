@IsTest
private class RemediationController_Test {
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
            'evt-rem-ctrl-' + Crypto.getRandomInteger(),
            new Map<String, Object>{ 'k' => 1 }
        );
        insert f;
        return f;
    }

    @IsTest
    static void getPermissionState_returnsBothKeys() {
        Test.startTest();
        Map<String, Boolean> state = RemediationController.getPermissionState();
        Test.stopTest();

        System.assertNotEquals(null, state, 'Permission state map must not be null');
        System.assert(state.containsKey('SecOps_Remediate_User'), 'Expected SecOps_Remediate_User key');
        System.assert(state.containsKey('SecOps_Remediate_App'), 'Expected SecOps_Remediate_App key');
    }

    @IsTest
    static void revokeOauthToken_withoutPermissionThrowsAuraHandled() {
        Security_Finding__c f = newFinding();
        Boolean threw = false;
        Test.startTest();
        try {
            RemediationController.revokeOauthToken(f.Id, null);
        } catch (AuraHandledException e) {
            threw = true;
        }
        Test.stopTest();
        System.assert(threw, 'Expected AuraHandledException without permission');
    }

    @IsTest
    static void killSession_withoutPermissionThrowsAuraHandled() {
        Security_Finding__c f = newFinding();
        Boolean threw = false;
        Test.startTest();
        try {
            RemediationController.killSession(f.Id, UserInfo.getUserId(), null);
        } catch (AuraHandledException e) {
            threw = true;
        }
        Test.stopTest();
        System.assert(threw);
    }

    @IsTest
    static void blockConnectedApp_withoutPermissionThrowsAuraHandled() {
        Security_Finding__c f = newFinding();
        Boolean threw = false;
        Test.startTest();
        try {
            RemediationController.blockConnectedApp(f.Id, '0H4xx0000004CAB');
        } catch (AuraHandledException e) {
            threw = true;
        }
        Test.stopTest();
        System.assert(threw);
    }

    @IsTest
    static void freezeUser_withoutPermissionThrowsAuraHandled() {
        Security_Finding__c f = newFinding();
        Boolean threw = false;
        Test.startTest();
        try {
            RemediationController.freezeUser(f.Id, UserInfo.getUserId());
        } catch (AuraHandledException e) {
            threw = true;
        }
        Test.stopTest();
        System.assert(threw);
    }

    @IsTest
    static void forcePasswordReset_withoutPermissionThrowsAuraHandled() {
        Security_Finding__c f = newFinding();
        Boolean threw = false;
        Test.startTest();
        try {
            RemediationController.forcePasswordReset(f.Id, UserInfo.getUserId());
        } catch (AuraHandledException e) {
            threw = true;
        }
        Test.stopTest();
        System.assert(threw);
    }
}
