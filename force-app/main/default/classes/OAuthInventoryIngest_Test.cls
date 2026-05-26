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

    @IsTest
    static void buildInventory_mapsRowFieldsToInventory() {
        Datetime now = Datetime.now();
        Map<String, Map<String, Object>> apps = new Map<String, Map<String, Object>>{
            '0H4000000000010' => new Map<String, Object>{
                'Name' => 'App A',
                'CreatedDate' => '2026-01-01T00:00:00.000+0000',
                'Scopes' => new List<String>{ 'api', 'refresh_token' }
            }
        };

        List<OAuth_App_Inventory__c> invs = OAuthInventoryIngest.buildInventory(apps, now);

        System.assertEquals(1, invs.size(), 'One inventory row per app');
        OAuth_App_Inventory__c inv = invs[0];
        System.assertEquals('0H4000000000010', inv.ConnectedApp_Id__c, 'ConnectedApp_Id__c is the map key');
        System.assertEquals(now, inv.Last_Seen__c, 'Last_Seen__c set to the passed-in timestamp');
        System.assertNotEquals(null, inv.Installed_Date__c, 'Installed_Date__c parsed from CreatedDate');
        System.assert(
            inv.Scope_Json__c != null && inv.Scope_Json__c.contains('refresh_token'),
            'Scope_Json__c serializes Scopes'
        );
    }

    @IsTest
    static void buildInventory_toleratesMissingAndBadFields() {
        Datetime now = Datetime.now();
        Map<String, Map<String, Object>> apps = new Map<String, Map<String, Object>>{
            '0H4000000000020' => new Map<String, Object>{ 'Name' => 'No Scopes No Date' },
            '0H4000000000021' => new Map<String, Object>{ 'CreatedDate' => 'not-a-date' }
        };

        List<OAuth_App_Inventory__c> invs = OAuthInventoryIngest.buildInventory(apps, now);

        System.assertEquals(2, invs.size(), 'Both rows produced');
        for (OAuth_App_Inventory__c inv : invs) {
            System.assertEquals(now, inv.Last_Seen__c, 'Last_Seen__c always set');
            if (inv.ConnectedApp_Id__c == '0H4000000000020') {
                System.assertEquals(null, inv.Installed_Date__c, 'No CreatedDate leaves Installed_Date__c null');
                System.assertEquals(null, inv.Scope_Json__c, 'No Scopes leaves Scope_Json__c null');
            } else {
                System.assertEquals(null, inv.Installed_Date__c, 'Unparseable CreatedDate is swallowed, stays null');
            }
        }
    }
}
