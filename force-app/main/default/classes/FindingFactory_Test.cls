@IsTest
private class FindingFactory_Test {
    @IsTest
    static void build_populatesAllFieldsAndDefaults() {
        Id runId = ScanRunService.start('Manual Scan');
        Id userId = UserInfo.getUserId();
        Map<String, Object> payload = new Map<String, Object>{ 'reason' => 'unit-test', 'count' => 3 };

        Security_Finding__c f = FindingFactory.build(
            runId,
            'Unit_Test_Rule',
            'Login Anomaly',
            SecOpsConstants.SEVERITY_HIGH,
            userId,
            null,
            'evt-123',
            payload
        );

        System.assertNotEquals(null, f, 'Factory should return a finding');
        System.assertEquals(runId, f.Scan_Run__c, 'Scan_Run should be wired');
        System.assertEquals('Unit_Test_Rule', f.Detection_Rule__c, 'Rule name should be set');
        System.assertEquals('Login Anomaly', f.Category__c, 'Category should be set');
        System.assertEquals(SecOpsConstants.SEVERITY_HIGH, f.Severity__c, 'Severity should be set');
        System.assertEquals(SecOpsConstants.STATUS_NEW, f.Status__c, 'Default status should be New');
        System.assertEquals(userId, f.Subject_User__c, 'Subject user should be set');
        System.assertEquals(null, f.Subject_App__c, 'Subject app should be null when not provided');
        System.assertEquals('evt-123', f.Source_Event_Id__c, 'Source event id should be set');
        System.assertNotEquals(null, f.Source_Event_Json__c, 'Source JSON should be serialized');
        System.assertEquals(SecOpsConstants.RISK_HIGH, f.Risk_Score__c, 'Risk score should follow severity');
    }

    @IsTest
    static void build_nullPayload_leavesJsonNull() {
        Id runId = ScanRunService.start('Manual Scan');
        Security_Finding__c f = FindingFactory.build(
            runId,
            'Null_Payload_Rule',
            'Setup Change',
            SecOpsConstants.SEVERITY_LOW,
            null,
            null,
            'evt-x',
            null
        );
        System.assertEquals(null, f.Source_Event_Json__c, 'Null payload should leave JSON null');
        System.assertEquals(SecOpsConstants.RISK_LOW, f.Risk_Score__c, 'Low severity should map to low risk');
    }
}
