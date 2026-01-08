//! Certificate Management Pages

use yew::prelude::*;

use crate::components::auth::Protected;

/// Certificate list page
#[function_component(Certificates)]
pub fn certificates() -> Html {
    html! {
        <Protected permission="view_certificates">
            <div class="page-header">
                <h1 class="page-title">{ "Certificates" }</h1>
                <p class="page-description">{ "Manage issued certificates" }</p>
            </div>

            // Actions bar
            <div class="flex justify-between items-center mb-6">
                <div class="flex space-x-4">
                    // Search
                    <input
                        type="text"
                        placeholder="Search certificates..."
                        class="form-input w-64"
                    />
                    // Filter dropdown
                    <select class="form-select">
                        <option>{ "All Status" }</option>
                        <option>{ "Active" }</option>
                        <option>{ "Revoked" }</option>
                        <option>{ "Expired" }</option>
                    </select>
                </div>
                <button class="btn-primary">
                    { "Issue Certificate" }
                </button>
            </div>

            // Certificates table
            <div class="card">
                <div class="overflow-x-auto">
                    <table class="table">
                        <thead class="table-header">
                            <tr>
                                <th class="table-header-cell">{ "Serial Number" }</th>
                                <th class="table-header-cell">{ "Subject" }</th>
                                <th class="table-header-cell">{ "Issuer" }</th>
                                <th class="table-header-cell">{ "Valid From" }</th>
                                <th class="table-header-cell">{ "Valid To" }</th>
                                <th class="table-header-cell">{ "Status" }</th>
                                <th class="table-header-cell">{ "Actions" }</th>
                            </tr>
                        </thead>
                        <tbody class="table-body">
                            <CertificateRow
                                serial="A1B2C3D4E5F6"
                                subject="CN=api.example.com"
                                issuer="CN=OstrichPKI Intermediate CA"
                                valid_from="2024-01-15"
                                valid_to="2025-01-15"
                                status="Active"
                            />
                            <CertificateRow
                                serial="F6E5D4C3B2A1"
                                subject="CN=web.example.com"
                                issuer="CN=OstrichPKI Intermediate CA"
                                valid_from="2024-02-01"
                                valid_to="2025-02-01"
                                status="Active"
                            />
                            <CertificateRow
                                serial="112233445566"
                                subject="CN=old-server.local"
                                issuer="CN=OstrichPKI Intermediate CA"
                                valid_from="2023-06-01"
                                valid_to="2024-06-01"
                                status="Revoked"
                            />
                        </tbody>
                    </table>
                </div>
            </div>
        </Protected>
    }
}

/// Certificate row properties
#[derive(Properties, PartialEq)]
struct CertificateRowProps {
    serial: &'static str,
    subject: &'static str,
    issuer: &'static str,
    valid_from: &'static str,
    valid_to: &'static str,
    status: &'static str,
}

/// Certificate table row
#[function_component(CertificateRow)]
fn certificate_row(props: &CertificateRowProps) -> Html {
    let status_class = match props.status {
        "Active" => "badge-success",
        "Revoked" => "badge-danger",
        "Expired" => "badge-warning",
        _ => "badge-gray",
    };

    html! {
        <tr class="table-row-hover">
            <td class="table-cell font-mono text-sm">{ props.serial }</td>
            <td class="table-cell">{ props.subject }</td>
            <td class="table-cell text-gray-500">{ props.issuer }</td>
            <td class="table-cell">{ props.valid_from }</td>
            <td class="table-cell">{ props.valid_to }</td>
            <td class="table-cell">
                <span class={status_class}>{ props.status }</span>
            </td>
            <td class="table-cell">
                <button class="text-blue-600 hover:text-blue-800 mr-2">{ "View" }</button>
                if props.status == "Active" {
                    <button class="text-red-600 hover:text-red-800">{ "Revoke" }</button>
                }
            </td>
        </tr>
    }
}

/// Certificate detail page properties
#[derive(Properties, PartialEq)]
pub struct CertificateDetailProps {
    pub id: String,
}

/// Certificate detail page
#[function_component(CertificateDetail)]
pub fn certificate_detail(props: &CertificateDetailProps) -> Html {
    html! {
        <Protected permission="view_certificates">
            <div class="page-header">
                <h1 class="page-title">{ "Certificate Details" }</h1>
                <p class="page-description">{ format!("Certificate ID: {}", props.id) }</p>
            </div>

            <div class="card">
                <div class="card-body">
                    <p class="text-gray-500">{ "Certificate details would be loaded here..." }</p>
                </div>
            </div>
        </Protected>
    }
}
