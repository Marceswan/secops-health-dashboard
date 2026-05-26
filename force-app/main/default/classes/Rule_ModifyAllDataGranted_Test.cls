@IsTest
private class Rule_ModifyAllDataGranted_Test {
    @IsTest
    static void evaluate_returnsList_withoutException() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'ModifyAllData_Granted');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_ModifyAllDataGranted().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Rule should always return a non-null list');
    }

    @IsTest
    static void developerName_isStable() {
        System.assertEquals('ModifyAllData_Granted', new Rule_ModifyAllDataGranted().getDeveloperName());
    }

    @IsTest
    static void evaluateRows_modifyAllDataAssignment_producesFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'ModifyAllData_Granted');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );

        // Building a real PermissionSet with PermissionsModifyAllData triggers a
        // 30+ permission dependency chain, so feed the rule an in-memory
        // PermissionSetAssignment (with its nested PermissionSet) via JSON.
        PermissionSetAssignment psa = (PermissionSetAssignment) JSON.deserialize(
            '{"attributes":{"type":"PermissionSetAssignment"},"AssigneeId":"' +
                u.Id +
                '","PermissionSetId":"0PS000000000001AAA","SystemModstamp":"2026-05-25T10:00:00.000Z",' +
                '"PermissionSet":{"attributes":{"type":"PermissionSet"},"Label":"Super Admin PS",' +
                '"PermissionsModifyAllData":true,"PermissionsViewAllData":true}}',
            PermissionSetAssignment.class
        );

        Test.startTest();
        List<Security_Finding__c> findings = Rule_ModifyAllDataGranted.evaluateRows(
            ctx,
            new List<PermissionSetAssignment>{ psa }
        );
        Test.stopTest();

        System.assertEquals(1, findings.size(), 'One privileged grant should yield one finding');
        System.assertEquals(u.Id, findings[0].Subject_User__c, 'Finding should target the granted user');
        System.assertEquals(SecOpsConstants.SEVERITY_HIGH, findings[0].Severity__c, 'Should be HIGH severity');
    }

    @IsTest
    static void evaluateRows_emptyInput_returnsEmpty() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'ModifyAllData_Granted');
        DetectionContext ctx = new DetectionContext(run.Id, Datetime.now().addHours(-24), Datetime.now(), false, false, cfg);

        List<Security_Finding__c> findings = Rule_ModifyAllDataGranted.evaluateRows(
            ctx,
            new List<PermissionSetAssignment>()
        );
        System.assertEquals(0, findings.size(), 'No rows yields no findings');
    }
}
