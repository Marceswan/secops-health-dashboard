@IsTest
private class OAuthInventoryIngest_Test {
    private class MockSuccess implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            HttpResponse res = new HttpResponse();
            res.setStatusCode(200);
            res.setHeader('Content-Type', 'application/json');
            res.setBody(
                '{"size":1,"records":[' +
                    '{"Id":"0H4xx0000004CAB","Name":"Mock App","CreatedDate":"2026-01-01T00:00:00.000+0000"}' +
                    ']}'
            );
            return res;
        }
    }

    @IsTest
    static void ingest_upsertsInventoryRow() {
        Test.setMock(HttpCalloutMock.class, new MockSuccess());
        Id runId = ScanRunService.start('Manual Scan');

        Test.startTest();
        System.enqueueJob(new OAuthInventoryIngest(runId));
        Test.stopTest();

        SecOps_Scan_Run__c run = [SELECT Error_Log__c FROM SecOps_Scan_Run__c WHERE Id = :runId];
        System.assert(
            run.Error_Log__c != null && run.Error_Log__c.contains('OAuthInventoryIngest'),
            'Ingest should append a log line'
        );

        Integer cnt = [SELECT COUNT() FROM OAuth_App_Inventory__c WHERE ConnectedApp_Id__c = '0H4xx0000004CAB'];
        System.assertEquals(1, cnt, 'Expected one OAuth_App_Inventory row upserted');
    }
}
