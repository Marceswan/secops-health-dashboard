import { LightningElement, wire, track } from 'lwc';
import listActiveUsers from '@salesforce/apex/InvestigateController.listActiveUsers';
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

    @wire(listActiveUsers, { limitSize: 100 })
    wiredUsers;

    get userOptions() {
        if (!this.wiredUsers || !this.wiredUsers.data) {
            return [];
        }
        return this.wiredUsers.data.map((u) => ({ label: u.Name, value: u.Id }));
    }

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
        this.selectedUserId = event.detail.value;
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
