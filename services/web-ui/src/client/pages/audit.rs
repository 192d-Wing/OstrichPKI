//! Audit Log Viewer Page
//!
//! COMPLIANCE MAPPING:
//! - NIAP PP-CA: FAU_SAR.1 (Audit Review)
//! - NIST 800-53: AU-6 (Audit Review, Analysis, and Reporting)

use yew::prelude::*;

use crate::components::auth::Protected;

/// Audit logs page
#[function_component(AuditLogs)]
pub fn audit_logs() -> Html {
    html! {
        <Protected permission="read_audit_log">
            <div class="page-header">
                <h1 class="page-title">{ "Audit Logs" }</h1>
                <p class="page-description">{ "View and search security audit records" }</p>
            </div>

            // Filters
            <div class="card mb-6">
                <div class="card-body">
                    <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                        <div>
                            <label class="form-label">{ "Event Type" }</label>
                            <select class="form-select">
                                <option>{ "All Events" }</option>
                                <option>{ "Authentication" }</option>
                                <option>{ "Authorization" }</option>
                                <option>{ "Certificate Issuance" }</option>
                                <option>{ "Certificate Revocation" }</option>
                                <option>{ "Key Operations" }</option>
                            </select>
                        </div>
                        <div>
                            <label class="form-label">{ "Actor" }</label>
                            <input type="text" class="form-input" placeholder="Username or ID" />
                        </div>
                        <div>
                            <label class="form-label">{ "Date Range" }</label>
                            <input type="date" class="form-input" />
                        </div>
                        <div>
                            <label class="form-label">{ "Outcome" }</label>
                            <select class="form-select">
                                <option>{ "All" }</option>
                                <option>{ "Success" }</option>
                                <option>{ "Failure" }</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>

            // Audit log table
            <div class="card">
                <div class="overflow-x-auto">
                    <table class="table">
                        <thead class="table-header">
                            <tr>
                                <th class="table-header-cell">{ "Timestamp" }</th>
                                <th class="table-header-cell">{ "Event Type" }</th>
                                <th class="table-header-cell">{ "Actor" }</th>
                                <th class="table-header-cell">{ "Target" }</th>
                                <th class="table-header-cell">{ "Action" }</th>
                                <th class="table-header-cell">{ "Outcome" }</th>
                            </tr>
                        </thead>
                        <tbody class="table-body">
                            <tr class="table-row-hover">
                                <td class="table-cell text-gray-500">{ "2024-01-15 14:32:15 UTC" }</td>
                                <td class="table-cell">{ "Authentication" }</td>
                                <td class="table-cell">{ "admin@example.com" }</td>
                                <td class="table-cell">{ "System" }</td>
                                <td class="table-cell">{ "Login" }</td>
                                <td class="table-cell"><span class="badge-success">{ "Success" }</span></td>
                            </tr>
                            <tr class="table-row-hover">
                                <td class="table-cell text-gray-500">{ "2024-01-15 14:30:45 UTC" }</td>
                                <td class="table-cell">{ "Certificate Issuance" }</td>
                                <td class="table-cell">{ "admin@example.com" }</td>
                                <td class="table-cell">{ "CN=api.example.com" }</td>
                                <td class="table-cell">{ "Issue" }</td>
                                <td class="table-cell"><span class="badge-success">{ "Success" }</span></td>
                            </tr>
                            <tr class="table-row-hover">
                                <td class="table-cell text-gray-500">{ "2024-01-15 14:28:00 UTC" }</td>
                                <td class="table-cell">{ "Authorization" }</td>
                                <td class="table-cell">{ "user@example.com" }</td>
                                <td class="table-cell">{ "/admin/users" }</td>
                                <td class="table-cell">{ "Access" }</td>
                                <td class="table-cell"><span class="badge-danger">{ "Denied" }</span></td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </Protected>
    }
}
