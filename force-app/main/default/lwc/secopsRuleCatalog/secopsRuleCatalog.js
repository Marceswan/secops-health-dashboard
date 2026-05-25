import { LightningElement, wire } from 'lwc';
import { refreshApex } from '@salesforce/apex';
import { ShowToastEvent } from 'lightning/platformShowToastEvent';
import listRules from '@salesforce/apex/RuleCatalogController.listRules';
import setRuleActive from '@salesforce/apex/RuleCatalogController.setRuleActive';

const COLUMNS = [
    { label: 'Rule', fieldName: 'MasterLabel', type: 'text', wrapText: true },
    { label: 'Category', fieldName: 'Category__c', type: 'text', initialWidth: 160 },
    { label: 'Severity', fieldName: 'Default_Severity__c', type: 'text', initialWidth: 110 },
    { label: 'Risk', fieldName: 'Default_Risk_Score__c', type: 'number', initialWidth: 80 },
    { label: 'Frequency', fieldName: 'Run_Frequency__c', type: 'text', initialWidth: 130 },
    { label: 'Active', fieldName: 'Is_Active__c', type: 'boolean', editable: true, initialWidth: 90 }
];

export default class SecopsRuleCatalog extends LightningElement {
    columns = COLUMNS;
    draftValues = [];
    wiredRulesResult;
    isSaving = false;

    @wire(listRules)
    wiredRules(result) {
        this.wiredRulesResult = result;
    }

    get rules() {
        return this.wiredRulesResult && this.wiredRulesResult.data ? this.wiredRulesResult.data : [];
    }

    get error() {
        return this.wiredRulesResult && this.wiredRulesResult.error;
    }

    get hasRules() {
        return this.rules.length > 0;
    }

    async handleSave(event) {
        const drafts = event.detail.draftValues || [];
        if (drafts.length === 0) {
            return;
        }
        this.isSaving = true;

        try {
            // The datatable keys edits by the row's "Id" property. Look up the
            // developer name from the wired rules list so the controller can
            // address the metadata row by API name.
            const byId = new Map(this.rules.map((r) => [r.Id, r]));
            const writes = drafts.map((d) => {
                const original = byId.get(d.Id);
                if (!original) {
                    return Promise.resolve();
                }
                return setRuleActive({
                    developerName: original.DeveloperName,
                    isActive: d.Is_Active__c
                });
            });
            await Promise.all(writes);

            this.dispatchEvent(new ShowToastEvent({
                title: 'Rule updates queued',
                message: 'Metadata deploy enqueued. Changes will land within a minute.',
                variant: 'success'
            }));
            this.draftValues = [];
            await refreshApex(this.wiredRulesResult);
        } catch (error) {
            this.dispatchEvent(new ShowToastEvent({
                title: 'Save failed',
                message: error.body ? error.body.message : error.message,
                variant: 'error'
            }));
        } finally {
            this.isSaving = false;
        }
    }

    handleCancel() {
        this.draftValues = [];
    }
}
