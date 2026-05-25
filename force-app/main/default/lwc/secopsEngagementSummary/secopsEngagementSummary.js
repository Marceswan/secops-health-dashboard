import { LightningElement } from 'lwc';

export default class SecopsEngagementSummary extends LightningElement {
    handleDownloadPdf() {
        window.open('/apex/SecOpsEngagementSummaryPdf', '_blank');
    }
}
