/**
 * ACME Service Load Test
 *
 * k6 load test for OstrichPKI ACME endpoints
 *
 * Usage:
 *   k6 run tests/performance/acme-load-test.js
 *   k6 run --vus 100 --duration 5m tests/performance/acme-load-test.js
 *
 * Environment Variables:
 *   ACME_BASE_URL - ACME service URL (default: http://localhost:8080)
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
const directoryLatency = new Trend('directory_latency');
const nonceLatency = new Trend('nonce_latency');
const healthLatency = new Trend('health_latency');

// Test configuration
export const options = {
    stages: [
        { duration: '30s', target: 10 },   // Ramp up to 10 users
        { duration: '1m', target: 50 },    // Ramp up to 50 users
        { duration: '2m', target: 50 },    // Stay at 50 users
        { duration: '1m', target: 100 },   // Ramp up to 100 users
        { duration: '2m', target: 100 },   // Stay at 100 users
        { duration: '30s', target: 0 },    // Ramp down
    ],
    thresholds: {
        http_req_duration: ['p(95)<500', 'p(99)<1000'],  // 95% < 500ms, 99% < 1s
        errors: ['rate<0.01'],                            // Error rate < 1%
        directory_latency: ['p(95)<200'],                 // Directory < 200ms
        nonce_latency: ['p(95)<100'],                     // Nonce < 100ms
        health_latency: ['p(95)<50'],                     // Health < 50ms
    },
};

const BASE_URL = __ENV.ACME_BASE_URL || 'http://localhost:8080';

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
        }) || errorRate.add(1);
    });

    group('ACME Directory', function () {
        const directoryRes = http.get(`${BASE_URL}/directory`);
        directoryLatency.add(directoryRes.timings.duration);

        check(directoryRes, {
            'directory status is 200': (r) => r.status === 200,
            'directory has newNonce': (r) => {
                try {
                    return JSON.parse(r.body).newNonce !== undefined;
                } catch {
                    return false;
                }
            },
            'directory has newAccount': (r) => {
                try {
                    return JSON.parse(r.body).newAccount !== undefined;
                } catch {
                    return false;
                }
            },
            'directory has newOrder': (r) => {
                try {
                    return JSON.parse(r.body).newOrder !== undefined;
                } catch {
                    return false;
                }
            },
        }) || errorRate.add(1);
    });

    group('Nonce Generation', function () {
        // First get directory to find nonce URL
        const directoryRes = http.get(`${BASE_URL}/directory`);
        if (directoryRes.status !== 200) {
            errorRate.add(1);
            return;
        }

        let nonceUrl;
        try {
            nonceUrl = JSON.parse(directoryRes.body).newNonce;
        } catch {
            errorRate.add(1);
            return;
        }

        const nonceRes = http.head(nonceUrl);
        nonceLatency.add(nonceRes.timings.duration);

        check(nonceRes, {
            'nonce status is 200': (r) => r.status === 200,
            'nonce header present': (r) => r.headers['Replay-Nonce'] !== undefined,
            'nonce is not empty': (r) => r.headers['Replay-Nonce'] && r.headers['Replay-Nonce'].length > 0,
        }) || errorRate.add(1);
    });

    sleep(0.5); // Pause between iterations
}

export function handleSummary(data) {
    return {
        'stdout': textSummary(data, { indent: ' ', enableColors: true }),
        'tests/performance/results/acme-load-test-summary.json': JSON.stringify(data),
    };
}

function textSummary(data, options) {
    const indent = options.indent || '';
    let output = '';

    output += `\n${indent}ACME Load Test Results\n`;
    output += `${indent}${'='.repeat(50)}\n\n`;

    output += `${indent}Scenarios:\n`;
    output += `${indent}  - VUs: ${data.metrics.vus ? data.metrics.vus.values.max : 'N/A'}\n`;
    output += `${indent}  - Iterations: ${data.metrics.iterations ? data.metrics.iterations.values.count : 'N/A'}\n`;

    output += `\n${indent}HTTP Metrics:\n`;
    if (data.metrics.http_req_duration) {
        const dur = data.metrics.http_req_duration.values;
        output += `${indent}  - Request Duration (p95): ${dur['p(95)'].toFixed(2)}ms\n`;
        output += `${indent}  - Request Duration (p99): ${dur['p(99)'].toFixed(2)}ms\n`;
    }

    output += `\n${indent}Custom Metrics:\n`;
    if (data.metrics.directory_latency) {
        output += `${indent}  - Directory Latency (p95): ${data.metrics.directory_latency.values['p(95)'].toFixed(2)}ms\n`;
    }
    if (data.metrics.nonce_latency) {
        output += `${indent}  - Nonce Latency (p95): ${data.metrics.nonce_latency.values['p(95)'].toFixed(2)}ms\n`;
    }
    if (data.metrics.health_latency) {
        output += `${indent}  - Health Latency (p95): ${data.metrics.health_latency.values['p(95)'].toFixed(2)}ms\n`;
    }

    output += `\n${indent}Thresholds:\n`;
    for (const [name, threshold] of Object.entries(data.thresholds || {})) {
        const status = threshold.ok ? '✓ PASS' : '✗ FAIL';
        output += `${indent}  - ${name}: ${status}\n`;
    }

    return output;
}
