import { LightningElement, wire } from 'lwc';
import { NavigationMixin } from 'lightning/navigation';
import { refreshApex } from '@salesforce/apex';
import { ShowToastEvent } from 'lightning/platformShowToastEvent';
import getOpenFindings from '@salesforce/apex/FindingQueueController.getOpenFindings';
import startScan from '@salesforce/apex/ScanController.startScan';

const COLUMNS = [
    { label: 'Severity', fieldName: 'severity', type: 'text', initialWidth: 100 },
    { label: 'Category', fieldName: 'category', type: 'text' },
    { label: 'Rule', fieldName: 'detectionRule', type: 'text' },
    { label: 'Risk', fieldName: 'riskScore', type: 'number', initialWidth: 80 },
    { label: 'User', fieldName: 'subjectUserName', type: 'text' },
    { label: 'App', fieldName: 'subjectAppName', type: 'text' },
    { label: 'Status', fieldName: 'status', type: 'text', initialWidth: 130 },
    { label: 'Detected', fieldName: 'createdDate', type: 'date',
        typeAttributes: { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' } },
    {
        type: 'action',
        typeAttributes: {
            rowActions: [
                { label: 'View', name: 'view' },
                { label: 'Acknowledge', name: 'ack' },
                { label: 'Dismiss', name: 'dismiss' }
            ]
        }
    }
];

export default class SecopsFindingQueue extends NavigationMixin(LightningElement) {
    columns = COLUMNS;
    isScanning = false;
    wiredFindingsResult;
    selectedIds = [];

    @wire(getOpenFindings, { limitSize: 200 })
    wiredFindings(result) {
        this.wiredFindingsResult = result;
    }

    get findingsData() {
        return this.wiredFindingsResult && this.wiredFindingsResult.data ? this.wiredFindingsResult.data : [];
    }

    get findingsError() {
        return this.wiredFindingsResult && this.wiredFindingsResult.error;
    }

    get hasData() {
        return this.findingsData.length > 0;
    }

    get hasSelection() {
        return this.selectedIds.length > 0;
    }

    handleRowSelection(event) {
        const rows = event.detail.selectedRows || [];
        this.selectedIds = rows.map((r) => r.id);
    }

    handleRowAction(event) {
        const actionName = event.detail.action.name;
        const row = event.detail.row;
        if (actionName === 'view') {
            this[NavigationMixin.Navigate]({
                type: 'standard__recordPage',
                attributes: {
                    recordId: row.id,
                    objectApiName: 'Security_Finding__c',
                    actionName: 'view'
                }
            });
        }
    }

    async handleRunScan() {
        this.isScanning = true;
        try {
            const runId = await startScan();
            this.dispatchEvent(new ShowToastEvent({
                title: 'Scan started',
                message: `Run ${runId} enqueued. Findings will appear here when complete.`,
                variant: 'success'
            }));
            await refreshApex(this.wiredFindingsResult);
        } catch (error) {
            this.dispatchEvent(new ShowToastEvent({
                title: 'Scan failed to start',
                message: error.body ? error.body.message : error.message,
                variant: 'error'
            }));
        } finally {
            this.isScanning = false;
        }
    }

    async handleBulkRefresh() {
        this.selectedIds = [];
        await refreshApex(this.wiredFindingsResult);
    }
}
