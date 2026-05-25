import { LightningElement, api, wire } from 'lwc';
import { getRecord, getFieldValue } from 'lightning/uiRecordApi';
import diffAgainstBaseline from '@salesforce/apex/InvestigateController.diffAgainstBaseline';
import SOURCE_JSON_FIELD from '@salesforce/schema/Security_Finding__c.Source_Event_Json__c';

const FIELDS = [SOURCE_JSON_FIELD];

export default class SecopsEventInspector extends LightningElement {
    @api recordId;
    wiredRecord;
    diffPaths = [];
    diffError;

    @wire(getRecord, { recordId: '$recordId', fields: FIELDS })
    wireRecordHandler(result) {
        this.wiredRecord = result;
        if (result.data && this.recordId) {
            this.loadDiff();
        }
    }

    async loadDiff() {
        try {
            this.diffPaths = await diffAgainstBaseline({ findingId: this.recordId });
        } catch (e) {
            this.diffError = e && e.body ? e.body.message : (e && e.message) || 'Unknown error';
            this.diffPaths = [];
        }
    }

    get prettyJson() {
        const raw = this.wiredRecord && this.wiredRecord.data
            ? getFieldValue(this.wiredRecord.data, SOURCE_JSON_FIELD)
            : null;
        if (!raw) {
            return '';
        }
        try {
            return JSON.stringify(JSON.parse(raw), null, 2);
        } catch (e) {
            return raw;
        }
    }

    get hasJson() {
        return !!this.prettyJson;
    }

    get hasDiff() {
        return this.diffPaths && this.diffPaths.length > 0;
    }

    get diffRows() {
        return (this.diffPaths || []).map((p) => ({ path: p }));
    }
}
