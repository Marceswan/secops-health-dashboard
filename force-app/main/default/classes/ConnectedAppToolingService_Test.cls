@IsTest
private class ConnectedAppToolingService_Test {
    private class MockSuccess implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            HttpResponse res = new HttpResponse();
            res.setStatusCode(200);
            res.setHeader('Content-Type', 'application/json');
            res.setBody(
                '{"size":2,"records":[' +
                    '{"Id":"0H4xx0000004CAB","Name":"App One","CreatedDate":"2026-01-01T00:00:00.000+0000"},' +
                    '{"Id":"0H4xx0000004CAC","Name":"App Two","CreatedDate":"2026-01-02T00:00:00.000+0000"}' +
                    ']}'
            );
            return res;
        }
    }

    private class MockError implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            HttpResponse res = new HttpResponse();
            res.setStatusCode(500);
            res.setBody('{}');
            return res;
        }
    }

    @IsTest
    static void fetchConnectedApps_parsesRecords() {
        Test.setMock(HttpCalloutMock.class, new MockSuccess());

        Test.startTest();
        Map<String, Map<String, Object>> result = ConnectedAppToolingService.fetchConnectedApps();
        Test.stopTest();

        System.assert(result.size() >= 1, 'Expected at least one parsed record');
        System.assert(result.containsKey('0H4xx0000004CAB'), 'Expected key for first record');
        Map<String, Object> row = result.get('0H4xx0000004CAB');
        System.assertEquals('App One', (String) row.get('Name'), 'Name should match mock payload');
    }

    @IsTest
    static void fetchConnectedApps_returnsEmptyOnError() {
        Test.setMock(HttpCalloutMock.class, new MockError());

        Test.startTest();
        Map<String, Map<String, Object>> result = ConnectedAppToolingService.fetchConnectedApps();
        Test.stopTest();

        System.assertEquals(0, result.size(), 'Non-200 response should return empty map');
    }
}
