import { LightningElement, track } from 'lwc';
import { ShowToastEvent } from 'lightning/platformShowToastEvent';
import readLastRun from '@salesforce/apex/ScanController.readLastRun';
import startScan from '@salesforce/apex/ScanController.startScan';

const POLL_MS = 5000;
const STATUS_RUNNING = 'Running';
const STATUS_COMPLETE = 'Complete';
const STATUS_FAILED = 'Failed';

export default class SecopsScanRunBanner extends LightningElement {
    @track lastRun;
    @track loading = true;
    @track starting = false;
    pollHandle;

    connectedCallback() {
        this.refresh();
    }

    disconnectedCallback() {
        this.stopPolling();
    }

    async refresh() {
        try {
            this.lastRun = await readLastRun();
            this.loading = false;
            if (this.isRunning) {
                this.startPolling();
            } else {
                this.stopPolling();
            }
        } catch (error) {
            this.loading = false;
            this.stopPolling();
        }
    }

    startPolling() {
        if (this.pollHandle) return;
        this.pollHandle = setInterval(() => this.refresh(), POLL_MS);
    }

    stopPolling() {
        if (this.pollHandle) {
            clearInterval(this.pollHandle);
            this.pollHandle = null;
        }
    }

    get isRunning() {
        return this.lastRun && this.lastRun.Status__c === STATUS_RUNNING;
    }

    get isComplete() {
        return this.lastRun && this.lastRun.Status__c === STATUS_COMPLETE;
    }

    get isFailed() {
        return this.lastRun && this.lastRun.Status__c === STATUS_FAILED;
    }

    get hasRun() {
        return this.lastRun != null;
    }

    get statusVariant() {
        if (this.isRunning) return 'warning';
        if (this.isFailed) return 'error';
        if (this.isComplete) return 'success';
        return 'inverse';
    }

    get statusLabel() {
        if (!this.lastRun) return 'No scans yet';
        return this.lastRun.Status__c;
    }

    get summaryLine() {
        if (!this.lastRun) return 'Run a scan to start collecting findings.';
        const r = this.lastRun;
        const findings = r.Findings_Created__c == null ? 0 : r.Findings_Created__c;
        const signals = r.Signals_Evaluated__c == null ? 0 : r.Signals_Evaluated__c;
        return `${r.Run_Type__c}: ${signals} signals evaluated, ${findings} findings created`;
    }

    get startedLabel() {
        return this.lastRun && this.lastRun.Started_At__c ? this.lastRun.Started_At__c : null;
    }

    get completedLabel() {
        return this.lastRun && this.lastRun.Completed_At__c ? this.lastRun.Completed_At__c : null;
    }

    get startButtonDisabled() {
        return this.starting || this.isRunning;
    }

    async handleStartScan() {
        this.starting = true;
        try {
            const runId = await startScan();
            this.dispatchEvent(new ShowToastEvent({
                title: 'Scan started',
                message: `Run ${runId} enqueued.`,
                variant: 'success'
            }));
            await this.refresh();
        } catch (error) {
            this.dispatchEvent(new ShowToastEvent({
                title: 'Scan failed to start',
                message: error.body ? error.body.message : error.message,
                variant: 'error'
            }));
        } finally {
            this.starting = false;
        }
    }
}
