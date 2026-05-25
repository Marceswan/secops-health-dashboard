@IsTest
private class RuleCatalogController_Test {
    @IsTest
    static void listRules_returnsNonNullList() {
        Test.startTest();
        List<Detection_Rule__mdt> rules = RuleCatalogController.listRules();
        Test.stopTest();
        System.assertNotEquals(null, rules, 'listRules should never return null');
    }

    @IsTest
    static void setRuleActive_noOpInTestContext() {
        Test.startTest();
        RuleCatalogController.setRuleActive('Failed_Login_Burst', true);
        RuleCatalogController.setRuleActive('Failed_Login_Burst', false);
        Test.stopTest();
        // No exception is the assertion; metadata deploys are suppressed in tests.
        System.assert(true, 'setRuleActive completed without exception');
    }

    @IsTest
    static void setRuleActive_handlesBlankInputs() {
        Test.startTest();
        RuleCatalogController.setRuleActive(null, true);
        RuleCatalogController.setRuleActive('', true);
        RuleCatalogController.setRuleActive('Some_Rule', null);
        Test.stopTest();
        System.assert(true, 'Blank inputs are tolerated');
    }
}
