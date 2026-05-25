import { LightningElement, api, wire } from 'lwc';
import { getRecord, getFieldValue, getRecordNotifyChange } from 'lightning/uiRecordApi';
import { ShowToastEvent } from 'lightning/platformShowToastEvent';
import acknowledge from '@salesforce/apex/WorkflowController.acknowledge';
import dismiss from '@salesforce/apex/WorkflowController.dismiss';
import markRemediated from '@salesforce/apex/WorkflowController.markRemediated';

import STATUS_FIELD from '@salesforce/schema/Security_Finding__c.Status__c';
import SEVERITY_FIELD from '@salesforce/schema/Security_Finding__c.Severity__c';
import CATEGORY_FIELD from '@salesforce/schema/Security_Finding__c.Category__c';
import RULE_FIELD from '@salesforce/schema/Security_Finding__c.Detection_Rule__c';
import USER_NAME_FIELD from '@salesforce/schema/Security_Finding__c.Subject_User__r.Name';
import APP_NAME_FIELD from '@salesforce/schema/Security_Finding__c.Subject_App__r.Name';
import SOURCE_JSON_FIELD from '@salesforce/schema/Security_Finding__c.Source_Event_Json__c';
import HISTORY_FIELD from '@salesforce/schema/Security_Finding__c.Action_History__c';
import DISMISSAL_REASON_FIELD from '@salesforce/schema/Security_Finding__c.Dismissal_Reason__c';
import RESOLVED_AT_FIELD from '@salesforce/schema/Security_Finding__c.Resolved_At__c';
import SUBJECT_USER_ID_FIELD from '@salesforce/schema/Security_Finding__c.Subject_User__c';
import SUBJECT_APP_ID_FIELD from '@salesforce/schema/Security_Finding__c.Subject_App__c';
import CONNECTED_APP_ID_FIELD from '@salesforce/schema/Security_Finding__c.Subject_App__r.ConnectedApp_Id__c';

const FIELDS = [
    STATUS_FIELD,
    SEVERITY_FIELD,
    CATEGORY_FIELD,
    RULE_FIELD,
    USER_NAME_FIELD,
    APP_NAME_FIELD,
    SOURCE_JSON_FIELD,
    HISTORY_FIELD,
    DISMISSAL_REASON_FIELD,
    RESOLVED_AT_FIELD,
    SUBJECT_USER_ID_FIELD,
    SUBJECT_APP_ID_FIELD,
    CONNECTED_APP_ID_FIELD
];

export default class SecopsFindingDetail extends LightningElement {
    @api recordId;
    record;
    wireError;
    busy = false;
    showDismissModal = false;
    dismissReason = '';

    @wire(getRecord, { recordId: '$recordId', fields: FIELDS })
    wiredFinding({ data, error }) {
        if (data) {
            this.record = data;
            this.wireError = undefined;
        } else if (error) {
            this.wireError = error;
            this.record = undefined;
        }
    }

    get status() { return getFieldValue(this.record, STATUS_FIELD); }
    get severity() { return getFieldValue(this.record, SEVERITY_FIELD); }
    get category() { return getFieldValue(this.record, CATEGORY_FIELD); }
    get rule() { return getFieldValue(this.record, RULE_FIELD); }
    get userName() { return getFieldValue(this.record, USER_NAME_FIELD); }
    get appName() { return getFieldValue(this.record, APP_NAME_FIELD); }
    get sourceJson() { return getFieldValue(this.record, SOURCE_JSON_FIELD); }
    get history() { return getFieldValue(this.record, HISTORY_FIELD); }
    get dismissalReason() { return getFieldValue(this.record, DISMISSAL_REASON_FIELD); }
    get resolvedAt() { return getFieldValue(this.record, RESOLVED_AT_FIELD); }

    get hasRecord() { return this.record != null; }

    /**
     * Lean DTO passed to the destructive remediation panel. Avoids handing
     * the full wire record across the component boundary.
     */
    get findingForPanel() {
        return {
            Id: this.recordId,
            Subject_User__c: getFieldValue(this.record, SUBJECT_USER_ID_FIELD),
            Subject_App__c: getFieldValue(this.record, SUBJECT_APP_ID_FIELD),
            ConnectedApp_Id__c: getFieldValue(this.record, CONNECTED_APP_ID_FIELD)
        };
    }

    handleRemediated() {
        getRecordNotifyChange([{ recordId: this.recordId }]);
    }

    get isResolved() {
        return this.status === 'Remediated' || this.status === 'Dismissed';
    }
    get isNew() { return this.status === 'New'; }
    get canAcknowledge() { return !this.busy && this.isNew; }
    get canRemediate() { return !this.busy && !this.isResolved; }
    get canDismiss() { return !this.busy && !this.isResolved; }
    get hasHistory() { return !!this.history; }
    get prettySource() {
        if (!this.sourceJson) return '';
        try {
            return JSON.stringify(JSON.parse(this.sourceJson), null, 2);
        } catch (e) {
            return this.sourceJson;
        }
    }

    async handleAcknowledge() {
        this.busy = true;
        try {
            await acknowledge({ findingId: this.recordId });
            this.afterAction('Acknowledged');
        } catch (error) {
            this.showError('Acknowledge failed', error);
        } finally {
            this.busy = false;
        }
    }

    async handleMarkRemediated() {
        this.busy = true;
        try {
            await markRemediated({ findingId: this.recordId });
            this.afterAction('Marked remediated');
        } catch (error) {
            this.showError('Remediate failed', error);
        } finally {
            this.busy = false;
        }
    }

    openDismissModal() {
        this.dismissReason = '';
        this.showDismissModal = true;
        // Bind so we can removeEventListener on close.
        this.boundEscHandler = (e) => {
            if (e.key === 'Escape') {
                this.closeDismissModal();
            }
        };
        window.addEventListener('keyup', this.boundEscHandler);
    }

    closeDismissModal() {
        this.showDismissModal = false;
        if (this.boundEscHandler) {
            window.removeEventListener('keyup', this.boundEscHandler);
            this.boundEscHandler = null;
        }
    }

    disconnectedCallback() {
        if (this.boundEscHandler) {
            window.removeEventListener('keyup', this.boundEscHandler);
            this.boundEscHandler = null;
        }
    }

    handleReasonChange(event) {
        this.dismissReason = event.target.value;
    }

    async handleDismissConfirm() {
        if (!this.dismissReason) {
            this.dispatchEvent(new ShowToastEvent({
                title: 'Reason required',
                message: 'Provide a reason before dismissing.',
                variant: 'warning'
            }));
            return;
        }
        this.busy = true;
        try {
            await dismiss({ findingId: this.recordId, reason: this.dismissReason });
            this.showDismissModal = false;
            this.afterAction('Dismissed');
        } catch (error) {
            this.showError('Dismiss failed', error);
        } finally {
            this.busy = false;
        }
    }

    afterAction(label) {
        this.dispatchEvent(new ShowToastEvent({
            title: label,
            message: 'Finding updated.',
            variant: 'success'
        }));
        getRecordNotifyChange([{ recordId: this.recordId }]);
    }

    showError(title, error) {
        this.dispatchEvent(new ShowToastEvent({
            title,
            message: error && error.body ? error.body.message : (error && error.message ? error.message : 'Unknown error'),
            variant: 'error'
        }));
    }
}
