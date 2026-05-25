import { LightningElement, wire } from 'lwc';
import { NavigationMixin } from 'lightning/navigation';
import getCrossUserHeatmap from '@salesforce/apex/InvestigateController.getCrossUserHeatmap';

const COLUMNS = [
    { label: 'User', fieldName: 'userName', type: 'text' },
    { label: 'Category', fieldName: 'category', type: 'text' },
    {
        label: 'Findings',
        fieldName: 'count',
        type: 'number',
        cellAttributes: { alignment: 'left' }
    },
    {
        type: 'button',
        typeAttributes: {
            label: 'Open queue',
            name: 'open_queue',
            variant: 'base'
        }
    }
];

export default class SecopsCrossUser extends NavigationMixin(LightningElement) {
    columns = COLUMNS;
    wiredHeatmap;

    @wire(getCrossUserHeatmap, { days: 30 })
    wiredHandler(result) {
        this.wiredHeatmap = result;
    }

    get rows() {
        return this.wiredHeatmap && this.wiredHeatmap.data ? this.wiredHeatmap.data : [];
    }

    get hasRows() {
        return this.rows.length > 0;
    }

    get loadError() {
        return this.wiredHeatmap && this.wiredHeatmap.error;
    }

    handleRowAction(event) {
        const action = event.detail.action.name;
        const row = event.detail.row;
        if (action === 'open_queue') {
            this[NavigationMixin.Navigate]({
                type: 'standard__objectPage',
                attributes: {
                    objectApiName: 'Security_Finding__c',
                    actionName: 'list'
                },
                state: {
                    filterName: '__Recent',
                    category: row.category
                }
            });
        }
    }
}
