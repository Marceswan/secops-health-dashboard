import { LightningElement, wire } from 'lwc';
import { NavigationMixin } from 'lightning/navigation';
import { ShowToastEvent } from 'lightning/platformShowToastEvent';
import getOpenFindings from '@salesforce/apex/FindingQueueController.getOpenFindings';

const CSV_COLUMNS = [
    { key: 'id', label: 'Id' },
    { key: 'detectionRule', label: 'DetectionRule' },
    { key: 'category', label: 'Category' },
    { key: 'severity', label: 'Severity' },
    { key: 'status', label: 'Status' },
    { key: 'riskScore', label: 'RiskScore' },
    { key: 'subjectUserName', label: 'User' },
    { key: 'subjectAppName', label: 'App' },
    { key: 'createdDate', label: 'Detected' }
];

const REPORT_DEVELOPER_NAME = 'SecOps_Findings_For_Investigation';

export default class SecopsExportBar extends NavigationMixin(LightningElement) {
    wiredFindings;
    busy = false;

    @wire(getOpenFindings, { limitSize: 1000 })
    wiredHandler(result) {
        this.wiredFindings = result;
    }

    get rows() {
        return this.wiredFindings && this.wiredFindings.data ? this.wiredFindings.data : [];
    }

    get canExport() {
        return !this.busy && this.rows.length > 0;
    }

    escape(value) {
        if (value === null || value === undefined) {
            return '';
        }
        const str = String(value);
        if (str.indexOf(',') >= 0 || str.indexOf('"') >= 0 || str.indexOf('\n') >= 0) {
            return '"' + str.replace(/"/g, '""') + '"';
        }
        return str;
    }

    buildCsv(rows) {
        const header = CSV_COLUMNS.map((c) => c.label).join(',');
        const body = rows
            .map((r) => CSV_COLUMNS.map((c) => this.escape(r[c.key])).join(','))
            .join('\n');
        return header + '\n' + body;
    }

    handleExportCsv() {
        this.busy = true;
        try {
            const csv = this.buildCsv(this.rows);
            const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = 'secops-findings.csv';
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
        } catch (e) {
            this.dispatchEvent(new ShowToastEvent({
                title: 'Export failed',
                message: e.message || 'Unable to build CSV',
                variant: 'error'
            }));
        } finally {
            this.busy = false;
        }
    }

    handleOpenReport() {
        this[NavigationMixin.Navigate]({
            type: 'standard__recordPage',
            attributes: {
                objectApiName: 'Report',
                actionName: 'view'
            },
            state: {
                reportDeveloperName: REPORT_DEVELOPER_NAME
            }
        });
    }
}
