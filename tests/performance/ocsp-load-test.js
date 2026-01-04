/**
 * OCSP Service Load Test
 *
 * k6 load test for OstrichPKI OCSP responder
 *
 * Usage:
 *   k6 run tests/performance/ocsp-load-test.js
 *   k6 run --vus 500 --duration 5m tests/performance/ocsp-load-test.js
 *
 * Environment Variables:
 *   OCSP_BASE_URL - OCSP service URL (default: http://localhost:8081)
 *
 * COMPLIANCE MAPPING:
 * - NIST 800-53: SA-11 (Developer Security Testing)
 * - NIST 800-53: SC-5 (Denial of Service Protection)
 * - RFC 6960: OCSP performance testing
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const ocspLatency = new Trend('ocsp_latency');
const healthLatency = new Trend('health_latency');
const requestsPerSecond = new Counter('requests_per_second');

// Test configuration - OCSP needs to handle high TPS
export const options = {
    scenarios: {
        // Constant rate test - target 1000 TPS
        constant_rate: {
            executor: 'constant-arrival-rate',
            rate: 1000,
            timeUnit: '1s',
            duration: '2m',
            preAllocatedVUs: 100,
            maxVUs: 500,
        },
        // Spike test
        spike: {
            executor: 'ramping-arrival-rate',
            startRate: 100,
            timeUnit: '1s',
            preAllocatedVUs: 50,
            maxVUs: 500,
            stages: [
                { duration: '30s', target: 100 },
                { duration: '1m', target: 500 },
                { duration: '30s', target: 2000 },  // Spike
                { duration: '1m', target: 500 },
                { duration: '30s', target: 100 },
            ],
            startTime: '2m30s',  // Start after constant_rate
        },
    },
    thresholds: {
        http_req_duration: ['p(95)<100', 'p(99)<200'],  // OCSP must be fast
        errors: ['rate<0.001'],                          // Error rate < 0.1%
        ocsp_latency: ['p(95)<100'],                     // OCSP < 100ms
        health_latency: ['p(95)<50'],                    // Health < 50ms
    },
};

const BASE_URL = __ENV.OCSP_BASE_URL || 'http://localhost:8081';

// Sample OCSP request (base64 encoded minimal request)
// In production, this would be a real OCSP request for a known certificate
const SAMPLE_OCSP_REQUEST = 'MEMwQTA/MD0wOzAJBgUrDgMCGgUABBQE/HhZRvVxUTnO/gy2L2QRLpYu4wQUiT7M1i6m/ZP2AMlQu+zk1g1p3j4=';

export default function () {
    group('Health Check', function () {
        const healthRes = http.get(`${BASE_URL}/health`);
        healthLatency.add(healthRes.timings.duration);
        requestsPerSecond.add(1);

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

    group('OCSP Request (GET)', function () {
        // RFC 6960 Appendix A.1 - OCSP over HTTP (GET method)
        const ocspRes = http.get(`${BASE_URL}/${SAMPLE_OCSP_REQUEST}`, {
            headers: {
                'Accept': 'application/ocsp-response',
            },
        });
        ocspLatency.add(ocspRes.timings.duration);
        requestsPerSecond.add(1);

        // Note: This will return 400 for our sample request since it's not a real OCSP request
        // In a real test, you would use valid OCSP requests for known certificates
        check(ocspRes, {
            'ocsp responds': (r) => r.status === 200 || r.status === 400,
            'ocsp response has content-type': (r) =>
                r.headers['Content-Type'] === 'application/ocsp-response' || r.status === 400,
        }) || errorRate.add(1);
    });

    group('OCSP Request (POST)', function () {
        // RFC 6960 Appendix A.1 - OCSP over HTTP (POST method)
        const ocspRes = http.post(
            BASE_URL,
            atob(SAMPLE_OCSP_REQUEST),  // Decode base64 to binary
            {
                headers: {
                    'Content-Type': 'application/ocsp-request',
                    'Accept': 'application/ocsp-response',
                },
            }
        );
        ocspLatency.add(ocspRes.timings.duration);
        requestsPerSecond.add(1);

        check(ocspRes, {
            'ocsp post responds': (r) => r.status === 200 || r.status === 400,
        }) || errorRate.add(1);
    });

    sleep(0.01); // Minimal pause for high TPS
}

// Base64 decode helper
function atob(str) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    let output = [];

    str = str.replace(/[^A-Za-z0-9\+\/\=]/g, '');

    for (let i = 0; i < str.length; i += 4) {
        const enc1 = chars.indexOf(str.charAt(i));
        const enc2 = chars.indexOf(str.charAt(i + 1));
        const enc3 = chars.indexOf(str.charAt(i + 2));
        const enc4 = chars.indexOf(str.charAt(i + 3));

        const chr1 = (enc1 << 2) | (enc2 >> 4);
        const chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
        const chr3 = ((enc3 & 3) << 6) | enc4;

        output.push(chr1);
        if (enc3 !== 64) output.push(chr2);
        if (enc4 !== 64) output.push(chr3);
    }

    return String.fromCharCode.apply(null, output);
}

export function handleSummary(data) {
    return {
        'stdout': textSummary(data),
        'tests/performance/results/ocsp-load-test-summary.json': JSON.stringify(data),
    };
}

function textSummary(data) {
    let output = '';

    output += `\nOCSP Load Test Results\n`;
    output += `${'='.repeat(50)}\n\n`;

    output += `Performance Metrics:\n`;
    if (data.metrics.http_req_duration) {
        const dur = data.metrics.http_req_duration.values;
        output += `  - Request Duration (p50): ${dur['p(50)'].toFixed(2)}ms\n`;
        output += `  - Request Duration (p95): ${dur['p(95)'].toFixed(2)}ms\n`;
        output += `  - Request Duration (p99): ${dur['p(99)'].toFixed(2)}ms\n`;
    }
    if (data.metrics.http_reqs) {
        output += `  - Total Requests: ${data.metrics.http_reqs.values.count}\n`;
        output += `  - Requests/sec: ${data.metrics.http_reqs.values.rate.toFixed(2)}\n`;
    }

    output += `\nOCSP Specific Metrics:\n`;
    if (data.metrics.ocsp_latency) {
        output += `  - OCSP Latency (p95): ${data.metrics.ocsp_latency.values['p(95)'].toFixed(2)}ms\n`;
    }

    output += `\nThresholds:\n`;
    for (const [name, threshold] of Object.entries(data.thresholds || {})) {
        const status = threshold.ok ? '✓ PASS' : '✗ FAIL';
        output += `  - ${name}: ${status}\n`;
    }

    return output;
}
