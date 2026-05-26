@IsTest
private class Rule_PrivilegedPermSetGranted_Test {
    @IsTest
    static void evaluate_returnsList_withoutException() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Privileged_PermSet_Granted');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );

        Test.startTest();
        List<Security_Finding__c> findings = new Rule_PrivilegedPermSetGranted().evaluate(ctx);
        Test.stopTest();

        System.assertNotEquals(null, findings, 'Rule should always return a non-null list');
    }

    @IsTest
    static void developerName_isStable() {
        System.assertEquals('Privileged_PermSet_Granted', new Rule_PrivilegedPermSetGranted().getDeveloperName());
    }

    @IsTest
    static void evaluateRows_privilegedAssignment_producesFinding() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        User u = TestDataFactory.standardUser();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Privileged_PermSet_Granted');
        DetectionContext ctx = new DetectionContext(
            run.Id,
            Datetime.now().addHours(-24),
            Datetime.now(),
            false,
            false,
            cfg
        );

        // Avoid the PermissionsModifyAllData dependency chain by feeding an
        // in-memory PermissionSetAssignment (admin-labelled set) via JSON.
        PermissionSetAssignment psa = (PermissionSetAssignment) JSON.deserialize(
            '{"attributes":{"type":"PermissionSetAssignment"},"AssigneeId":"' +
                u.Id +
                '","PermissionSetId":"0PS000000000002AAA","SystemModstamp":"2026-05-25T10:00:00.000Z",' +
                '"PermissionSet":{"attributes":{"type":"PermissionSet"},"Label":"Org admin access",' +
                '"PermissionsModifyAllData":false,"PermissionsManageUsers":true}}',
            PermissionSetAssignment.class
        );

        Test.startTest();
        List<Security_Finding__c> findings = Rule_PrivilegedPermSetGranted.evaluateRows(
            ctx,
            new List<PermissionSetAssignment>{ psa }
        );
        Test.stopTest();

        System.assertEquals(1, findings.size(), 'One privileged grant should yield one finding');
        System.assertEquals(u.Id, findings[0].Subject_User__c, 'Finding should target the granted user');
        System.assertEquals(75, findings[0].Risk_Score__c, 'Risk score should be 75');
        System.assertEquals(SecOpsConstants.SEVERITY_HIGH, findings[0].Severity__c, 'Should be HIGH severity');
    }

    @IsTest
    static void evaluateRows_emptyInput_returnsEmpty() {
        SecOps_Scan_Run__c run = TestDataFactory.createScanRun();
        Detection_Rule__mdt cfg = new Detection_Rule__mdt(DeveloperName = 'Privileged_PermSet_Granted');
        DetectionContext ctx = new DetectionContext(run.Id, Datetime.now().addHours(-24), Datetime.now(), false, false, cfg);

        List<Security_Finding__c> findings = Rule_PrivilegedPermSetGranted.evaluateRows(
            ctx,
            new List<PermissionSetAssignment>()
        );
        System.assertEquals(0, findings.size(), 'No rows yields no findings');
    }
}
