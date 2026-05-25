import { LightningElement, wire } from 'lwc';
import getRiskTrend from '@salesforce/apex/PostureController.getRiskTrend';

const CHART_WIDTH = 600;
const CHART_HEIGHT = 200;
const PADDING_LEFT = 36;
const PADDING_RIGHT = 12;
const PADDING_TOP = 12;
const PADDING_BOTTOM = 24;

export default class SecopsRiskTrend extends LightningElement {
    chartWidth = CHART_WIDTH;
    chartHeight = CHART_HEIGHT;
    wiredResult;

    @wire(getRiskTrend, { days: 90 })
    wiredTrend(result) {
        this.wiredResult = result;
    }

    get trendData() {
        return this.wiredResult && this.wiredResult.data ? this.wiredResult.data : [];
    }

    get hasError() {
        return this.wiredResult && this.wiredResult.error;
    }

    get hasData() {
        return this.trendData.length > 0;
    }

    get maxValue() {
        let max = 1;
        for (const row of this.trendData) {
            if (row.criticalCount > max) max = row.criticalCount;
            if (row.highCount > max) max = row.highCount;
        }
        return max;
    }

    /** Build SVG polyline points string for criticalCount series. */
    get criticalPoints() {
        return this.buildPoints('criticalCount');
    }

    /** Build SVG polyline points string for highCount series. */
    get highPoints() {
        return this.buildPoints('highCount');
    }

    buildPoints(fieldName) {
        const rows = this.trendData;
        if (rows.length === 0) {
            return '';
        }
        const usableWidth = CHART_WIDTH - PADDING_LEFT - PADDING_RIGHT;
        const usableHeight = CHART_HEIGHT - PADDING_TOP - PADDING_BOTTOM;
        const xStep = rows.length > 1 ? usableWidth / (rows.length - 1) : 0;
        const max = this.maxValue;
        return rows
            .map((row, i) => {
                const x = PADDING_LEFT + xStep * i;
                const y = PADDING_TOP + usableHeight - (row[fieldName] / max) * usableHeight;
                return `${x.toFixed(1)},${y.toFixed(1)}`;
            })
            .join(' ');
    }

    /** Y-axis label values: 0, 25%, 50%, 75%, 100% of max. */
    get yLabels() {
        const max = this.maxValue;
        const usableHeight = CHART_HEIGHT - PADDING_TOP - PADDING_BOTTOM;
        return [0, 0.25, 0.5, 0.75, 1].map((pct) => ({
            key: `y-${pct}`,
            value: Math.round(max * pct),
            y: (PADDING_TOP + usableHeight - pct * usableHeight).toFixed(1)
        }));
    }

    /** X-axis labels: first, middle, last date. */
    get xLabels() {
        const rows = this.trendData;
        if (rows.length === 0) return [];
        const usableWidth = CHART_WIDTH - PADDING_LEFT - PADDING_RIGHT;
        const lastIdx = rows.length - 1;
        const midIdx = Math.floor(lastIdx / 2);
        const xStep = rows.length > 1 ? usableWidth / lastIdx : 0;
        return [
            { key: 'x-0', label: rows[0].date, x: PADDING_LEFT.toFixed(1) },
            {
                key: 'x-mid',
                label: rows[midIdx].date,
                x: (PADDING_LEFT + xStep * midIdx).toFixed(1)
            },
            {
                key: 'x-last',
                label: rows[lastIdx].date,
                x: (PADDING_LEFT + xStep * lastIdx).toFixed(1)
            }
        ];
    }
}
