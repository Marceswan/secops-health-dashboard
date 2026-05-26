import { LightningElement, track } from 'lwc';
import getTimelineForUser from '@salesforce/apex/InvestigateController.getTimelineForUser';

const DEFAULT_DAYS = 30;
const SEVERITY_CLASS = {
    Critical: 'dot dot-critical',
    High: 'dot dot-high',
    Medium: 'dot dot-medium',
    Low: 'dot dot-low'
};

export default class SecopsTimeline extends LightningElement {
    @track selectedUserId;
    @track entries = [];
    @track loadError;
    days = DEFAULT_DAYS;

    // lightning-record-picker config: search Name + Username, show Name with
    // Username as secondary, restrict to active users only.
    matchingInfo = {
        primaryField: { fieldPath: 'Name' },
        additionalFields: [{ fieldPath: 'Username' }]
    };
    displayInfo = {
        primaryField: 'Name',
        additionalFields: ['Username']
    };
    userFilter = {
        criteria: [{ fieldPath: 'IsActive', operator: 'eq', value: true }]
    };

    get hasEntries() {
        return this.entries && this.entries.length > 0;
    }

    get hasSelection() {
        return !!this.selectedUserId;
    }

    get displayEntries() {
        return this.entries.map((e) => ({
            ...e,
            dotClass: SEVERITY_CLASS[e.severity] || 'dot dot-low',
            tsFormatted: e.ts ? new Date(e.ts).toLocaleString() : ''
        }));
    }

    handleUserChange(event) {
        // lightning-record-picker emits the picked record id on event.detail.recordId
        // (null when cleared); lightning-combobox emitted event.detail.value.
        this.selectedUserId = event.detail.recordId || undefined;
        this.loadTimeline();
    }

    async loadTimeline() {
        this.loadError = undefined;
        this.entries = [];
        if (!this.selectedUserId) {
            return;
        }
        try {
            const rows = await getTimelineForUser({
                userId: this.selectedUserId,
                days: this.days
            });
            this.entries = rows || [];
        } catch (e) {
            this.loadError = e && e.body ? e.body.message : (e && e.message) || 'Unknown error';
        }
    }
}
