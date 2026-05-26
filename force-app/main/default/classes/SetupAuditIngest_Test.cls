@IsTest
private class SetupAuditIngest_Test {
    @IsTest
    static void enqueue_doesNotFailScanRun() {
        Id runId = ScanRunService.start('Manual Scan');

        Test.startTest();
        System.enqueueJob(new SetupAuditIngest(runId));
        Test.stopTest();

        SecOps_Scan_Run__c run = [SELECT Status__c, Error_Log__c FROM SecOps_Scan_Run__c WHERE Id = :runId];
        System.assertNotEquals('Failed', run.Status__c, 'SetupAuditIngest must not fail the Scan_Run');
        System.assert(
            run.Error_Log__c != null && run.Error_Log__c.contains('SetupAuditIngest'),
            'Log should reference SetupAuditIngest'
        );
    }

    @IsTest
    static void buildEvents_mapsRowFieldsToSecurityEvents() {
        Id uId = TestDataFactory.standardUser().Id;
        SetupAuditTrail t1 = (SetupAuditTrail) JSON.deserialize(
            '{"attributes":{"type":"SetupAuditTrail"},"Action":"PermSetAssign","Section":"Manage Users",' +
                '"Display":"Assigned perm set","CreatedById":"' +
                uId +
                '","CreatedDate":"2026-01-15T10:00:00.000Z"}',
            SetupAuditTrail.class
        );
        SetupAuditTrail t2 = (SetupAuditTrail) JSON.deserialize(
            '{"attributes":{"type":"SetupAuditTrail"},"Action":"profileEdit","Section":"Profiles",' +
                '"Display":"Edited profile","CreatedById":"' +
                uId +
                '","CreatedDate":"2026-02-20T08:30:00.000Z"}',
            SetupAuditTrail.class
        );

        List<Security_Event__c> events = SetupAuditIngest.buildEvents(new List<SetupAuditTrail>{ t1, t2 });

        System.assertEquals(2, events.size(), 'One event per source row');
        System.assertEquals('SetupAuditTrail', events[0].Event_Type__c, 'Event_Type__c must be SetupAuditTrail');
        System.assertEquals(t1.CreatedDate, events[0].Event_Time__c, 'Event_Time__c maps from CreatedDate');
        System.assertEquals(uId, events[0].User__c, 'User__c maps from CreatedById');
        System.assert(
            events[0].Source_Json__c != null && events[0].Source_Json__c.contains('PermSetAssign'),
            'Source_Json__c should serialize the source row'
        );
        System.assertEquals(t2.CreatedDate, events[1].Event_Time__c, 'Second row CreatedDate maps through');
    }

    @IsTest
    static void buildEvents_emptyInputReturnsEmptyList() {
        List<Security_Event__c> events = SetupAuditIngest.buildEvents(new List<SetupAuditTrail>());
        System.assertEquals(0, events.size(), 'Empty input yields no events');
    }
}
