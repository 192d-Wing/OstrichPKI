/**
 * CA Service Load Test
 *
 * k6 load test for OstrichPKI Certificate Authority endpoints
 *
 * Usage:
 *   k6 run tests/performance/ca-load-test.js
 *   k6 run --vus 50 --duration 5m tests/performance/ca-load-test.js
 *
 * Environment Variables:
 *   CA_BASE_URL - CA service URL (default: http://localhost:8082)
 *
 * COMPLIANCE MAPPING:
 * - NIST 800-53: SA-11 (Developer Security Testing)
 * - NIST 800-53: SC-5 (Denial of Service Protection)
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const healthLatency = new Trend('health_latency');
const readyLatency = new Trend('ready_latency');

// Test configuration - CA operations are slower due to crypto
export const options = {
    stages: [
        { duration: '30s', target: 10 },   // Ramp up to 10 users
        { duration: '1m', target: 25 },    // Ramp up to 25 users
        { duration: '2m', target: 25 },    // Stay at 25 users
        { duration: '1m', target: 50 },    // Ramp up to 50 users
        { duration: '2m', target: 50 },    // Stay at 50 users
        { duration: '30s', target: 0 },    // Ramp down
    ],
    thresholds: {
        http_req_duration: ['p(95)<1000', 'p(99)<2000'],  // CA is slower
        errors: ['rate<0.01'],                             // Error rate < 1%
        health_latency: ['p(95)<100'],                     // Health < 100ms
        ready_latency: ['p(95)<500'],                      // Ready < 500ms (checks HSM)
    },
};

const BASE_URL = __ENV.CA_BASE_URL || 'http://localhost:8082';

export default function () {
    group('Health Check', function () {
        const healthRes = http.get(`${BASE_URL}/health`);
        healthLatency.add(healthRes.timings.duration);

        check(healthRes, {
            'health status is 200': (r) => r.status === 200,
            'health response is healthy': (r) => {
                try {
                    return JSON.parse(r.body).status === 'healthy';
                } catch {
                    return false;
                }
            },
            'health service is ostrich-ca': (r) => {
                try {
                    return JSON.parse(r.body).service === 'ostrich-ca';
                } catch {
                    return false;
                }
            },
        }) || errorRate.add(1);
    });

    group('Readiness Check', function () {
        const readyRes = http.get(`${BASE_URL}/ready`);
        readyLatency.add(readyRes.timings.duration);

        check(readyRes, {
            'ready responds': (r) => r.status === 200 || r.status === 503,
            'ready has components': (r) => {
                try {
                    const body = JSON.parse(r.body);
                    return body.components !== undefined || r.status === 503;
                } catch {
                    return false;
                }
            },
        }) || errorRate.add(1);
    });

    sleep(0.5); // Pause between iterations
}

export function handleSummary(data) {
    return {
        'stdout': textSummary(data),
        'tests/performance/results/ca-load-test-summary.json': JSON.stringify(data),
    };
}

function textSummary(data) {
    let output = '';

    output += `\nCA Service Load Test Results\n`;
    output += `${'='.repeat(50)}\n\n`;

    output += `Scenarios:\n`;
    output += `  - VUs: ${data.metrics.vus ? data.metrics.vus.values.max : 'N/A'}\n`;
    output += `  - Iterations: ${data.metrics.iterations ? data.metrics.iterations.values.count : 'N/A'}\n`;

    output += `\nHTTP Metrics:\n`;
    if (data.metrics.http_req_duration) {
        const dur = data.metrics.http_req_duration.values;
        output += `  - Request Duration (p95): ${dur['p(95)'].toFixed(2)}ms\n`;
        output += `  - Request Duration (p99): ${dur['p(99)'].toFixed(2)}ms\n`;
    }

    output += `\nCustom Metrics:\n`;
    if (data.metrics.health_latency) {
        output += `  - Health Latency (p95): ${data.metrics.health_latency.values['p(95)'].toFixed(2)}ms\n`;
    }
    if (data.metrics.ready_latency) {
        output += `  - Ready Latency (p95): ${data.metrics.ready_latency.values['p(95)'].toFixed(2)}ms\n`;
    }

    output += `\nThresholds:\n`;
    for (const [name, threshold] of Object.entries(data.thresholds || {})) {
        const status = threshold.ok ? '✓ PASS' : '✗ FAIL';
        output += `  - ${name}: ${status}\n`;
    }

    return output;
}
