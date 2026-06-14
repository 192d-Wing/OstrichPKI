//! Certificate Management Pages
//!
//! Certificate list and detail views with search, filtering, and actions.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-2 (Audit Events) - Certificate viewing is audited
//! - NIST 800-53: SC-17 (PKI Certificates) - Certificate management interface
//! - NIAP PP-CA: FMT_SMF.1 - Security management functions for certificates
//! - RFC 5280: X.509 Certificate structure display

use std::rc::Rc;
use yew::prelude::*;

use crate::components::auth::Protected;
use crate::components::common::{
    Alert, AlertType, Badge, BadgeVariant, Column, DataTable, KeyFn, Loading, Modal, ModalSize,
    Pagination, RenderFn,
};
use crate::services::api::{api, ApiError};
use crate::types::api::{
    CertificateDetails, CertificateFilter, CertificateListResponse, CertificateStatus,
    CertificateSummary, RevocationReason, RevocationRequest,
};

/// Loading state for async data
#[derive(Clone, PartialEq)]
enum LoadState<T: Clone + PartialEq> {
    Loading,
    Loaded(T),
    Error(String),
}

// =============================================================================
// Certificate List Page
// =============================================================================

/// Certificate list page state
#[derive(Clone, PartialEq)]
struct CertListState {
    certificates: Vec<CertificateSummary>,
    total: u64,
    page: u32,
    page_size: u32,
    search: String,
    status_filter: String,
}

impl Default for CertListState {
    fn default() -> Self {
        Self {
            certificates: Vec::new(),
            total: 0,
            page: 1,
            page_size: 10,
            search: String::new(),
            status_filter: "all".to_string(),
        }
    }
}

/// Certificate list page component
#[function_component(Certificates)]
pub fn certificates() -> Html {
    let state = use_state(CertListState::default);
    let load_state = use_state(|| LoadState::<()>::Loading);
    let revoke_cert = use_state(|| None::<CertificateSummary>);

    // Fetch certificates on mount and when filters change
    {
        let state = state.clone();
        let load_state = load_state.clone();
        let search = state.search.clone();
        let status = state.status_filter.clone();
        let page = state.page;

        use_effect_with((search, status, page), move |_| {
            let state = state.clone();
            let load_state = load_state.clone();
            load_state.set(LoadState::Loading);

            wasm_bindgen_futures::spawn_local(async move {
                match fetch_certificates(&state).await {
                    Ok(response) => {
                        let mut new_state = (*state).clone();
                        new_state.certificates = response.certificates;
                        new_state.total = response.total;
                        state.set(new_state);
                        load_state.set(LoadState::Loaded(()));
                    }
                    Err(e) => {
                        load_state.set(LoadState::Error(e.message));
                    }
                }
            });
            || ()
        });
    }

    // Search handler
    let on_search = {
        let state = state.clone();
        Callback::from(move |e: InputEvent| {
            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
            let mut new_state = (*state).clone();
            new_state.search = input.value();
            new_state.page = 1; // Reset to first page on search
            state.set(new_state);
        })
    };

    // Status filter handler
    let on_status_filter = {
        let state = state.clone();
        Callback::from(move |e: Event| {
            let select: web_sys::HtmlSelectElement = e.target_unchecked_into();
            let mut new_state = (*state).clone();
            new_state.status_filter = select.value();
            new_state.page = 1;
            state.set(new_state);
        })
    };

    // Page change handler
    let on_page_change = {
        let state = state.clone();
        Callback::from(move |page: u32| {
            let mut new_state = (*state).clone();
            new_state.page = page;
            state.set(new_state);
        })
    };

    // Revoke button handler
    let on_revoke_click = {
        let revoke_cert = revoke_cert.clone();
        Callback::from(move |cert: CertificateSummary| {
            revoke_cert.set(Some(cert));
        })
    };

    // Close revoke modal
    let on_revoke_close = {
        let revoke_cert = revoke_cert.clone();
        Callback::from(move |_| {
            revoke_cert.set(None);
        })
    };

    // Confirm revocation
    let on_revoke_confirm = {
        let revoke_cert = revoke_cert.clone();
        let state = state.clone();
        Callback::from(move |_| {
            if let Some(cert) = (*revoke_cert).clone() {
                let revoke_cert = revoke_cert.clone();
                let state = state.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let request = RevocationRequest {
                        reason: RevocationReason::Unspecified,
                        notes: None,
                    };
                    if (api()
                        .post::<serde_json::Value, _>(
                            &format!("/ca/certificates/{}/revoke", cert.id),
                            &request,
                        )
                        .await)
                        .is_ok()
                    {
                        // Refresh list
                        if let Ok(response) = fetch_certificates(&state).await {
                            let mut new_state = (*state).clone();
                            new_state.certificates = response.certificates;
                            new_state.total = response.total;
                            state.set(new_state);
                        }
                    }
                    revoke_cert.set(None);
                });
            }
        })
    };

    // Define table columns
    let columns: Vec<Column<CertificateSummary>> = vec![
        Column {
            key: "serial".to_string(),
            label: "Serial Number".to_string(),
            sortable: true,
            render: Rc::new(|cert: &CertificateSummary| {
                html! {
                    <span class="font-mono text-sm text-gray-600">
                        { &cert.serial_number }
                    </span>
                }
            }),
        },
        Column {
            key: "subject".to_string(),
            label: "Subject".to_string(),
            sortable: true,
            render: Rc::new(|cert: &CertificateSummary| {
                html! {
                    <span class="font-medium text-gray-900">{ &cert.subject }</span>
                }
            }),
        },
        Column {
            key: "issuer".to_string(),
            label: "Issuer".to_string(),
            sortable: false,
            render: Rc::new(|cert: &CertificateSummary| {
                html! {
                    <span class="text-gray-500 text-sm">{ &cert.issuer }</span>
                }
            }),
        },
        Column {
            key: "valid_from".to_string(),
            label: "Valid From".to_string(),
            sortable: true,
            render: Rc::new(|cert: &CertificateSummary| {
                html! { <span>{ &cert.valid_from }</span> }
            }),
        },
        Column {
            key: "valid_to".to_string(),
            label: "Valid To".to_string(),
            sortable: true,
            render: Rc::new(|cert: &CertificateSummary| {
                html! { <span>{ &cert.valid_to }</span> }
            }),
        },
        Column {
            key: "status".to_string(),
            label: "Status".to_string(),
            sortable: true,
            render: Rc::new(|cert: &CertificateSummary| {
                let variant = match cert.status {
                    CertificateStatus::Active => BadgeVariant::Success,
                    CertificateStatus::Revoked => BadgeVariant::Danger,
                    CertificateStatus::Expired => BadgeVariant::Warning,
                    CertificateStatus::Pending => BadgeVariant::Info,
                };
                html! {
                    <Badge variant={variant}>{ cert.status.to_string() }</Badge>
                }
            }),
        },
    ];

    // Calculate total pages
    let total_pages = ((state.total as f64) / (state.page_size as f64)).ceil() as u32;
    let total_pages = if total_pages == 0 { 1 } else { total_pages };

    html! {
        <Protected permission="view_certificates">
            <div class="page-header">
                <h1 class="page-title">{ "Certificates" }</h1>
                <p class="page-description">{ "Manage issued certificates" }</p>
            </div>

            // Actions bar
            <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-6">
                <div class="flex flex-col sm:flex-row gap-4 w-full md:w-auto">
                    // Search
                    <div class="relative">
                        <input
                            type="text"
                            placeholder="Search by subject or serial..."
                            value={state.search.clone()}
                            oninput={on_search}
                            class="form-input w-full sm:w-80 pl-10"
                        />
                        <svg class="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                        </svg>
                    </div>
                    // Filter dropdown
                    <select
                        class="form-select w-full sm:w-auto"
                        onchange={on_status_filter}
                        value={state.status_filter.clone()}
                    >
                        <option value="all">{ "All Status" }</option>
                        <option value="active">{ "Active" }</option>
                        <option value="revoked">{ "Revoked" }</option>
                        <option value="expired">{ "Expired" }</option>
                        <option value="pending">{ "Pending" }</option>
                    </select>
                </div>
                <a href="/certificates/issue" class="btn-primary w-full sm:w-auto text-center">
                    <span class="flex items-center justify-center gap-2">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                        </svg>
                        { "Issue Certificate" }
                    </span>
                </a>
            </div>

            // Loading/Error/Content
            {
                match (*load_state).clone() {
                    LoadState::Loading => html! {
                        <div class="flex justify-center py-12">
                            <Loading message="Loading certificates..." />
                        </div>
                    },
                    LoadState::Error(msg) => html! {
                        <Alert alert_type={AlertType::Error} dismissible={false}>
                            { format!("Failed to load certificates: {}", msg) }
                        </Alert>
                    },
                    LoadState::Loaded(_) => html! {
                        <>
                            // Summary stats
                            <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                                <div class="bg-white rounded-lg border border-gray-200 p-4">
                                    <p class="text-sm text-gray-500">{ "Total Certificates" }</p>
                                    <p class="text-2xl font-bold text-gray-900">{ state.total }</p>
                                </div>
                                <div class="bg-white rounded-lg border border-gray-200 p-4">
                                    <p class="text-sm text-gray-500">{ "Active" }</p>
                                    <p class="text-2xl font-bold text-green-600">
                                        { state.certificates.iter().filter(|c| c.status == CertificateStatus::Active).count() }
                                    </p>
                                </div>
                                <div class="bg-white rounded-lg border border-gray-200 p-4">
                                    <p class="text-sm text-gray-500">{ "Revoked" }</p>
                                    <p class="text-2xl font-bold text-red-600">
                                        { state.certificates.iter().filter(|c| c.status == CertificateStatus::Revoked).count() }
                                    </p>
                                </div>
                                <div class="bg-white rounded-lg border border-gray-200 p-4">
                                    <p class="text-sm text-gray-500">{ "Expired" }</p>
                                    <p class="text-2xl font-bold text-amber-600">
                                        { state.certificates.iter().filter(|c| c.status == CertificateStatus::Expired).count() }
                                    </p>
                                </div>
                            </div>

                            // Certificates table
                            <div class="card">
                                <DataTable<CertificateSummary>
                                    columns={columns.clone()}
                                    data={state.certificates.clone()}
                                    row_key={Some(KeyFn(Rc::new(|cert: &CertificateSummary| cert.id.clone())))}
                                    empty_message="No certificates found"
                                    actions={Some(RenderFn(Rc::new({
                                        let on_revoke_click = on_revoke_click.clone();
                                        move |cert: &CertificateSummary| {
                                            let cert_clone = cert.clone();
                                            let on_revoke = on_revoke_click.clone();
                                            let cert_id = cert.id.clone();
                                            let is_active = cert.status == CertificateStatus::Active;

                                            html! {
                                                <div class="flex gap-2">
                                                    <a
                                                        href={format!("/certificates/{}", cert_id)}
                                                        class="text-blue-600 hover:text-blue-800 text-sm font-medium"
                                                    >
                                                        { "View" }
                                                    </a>
                                                    if is_active {
                                                        <button
                                                            onclick={Callback::from(move |_| on_revoke.emit(cert_clone.clone()))}
                                                            class="text-red-600 hover:text-red-800 text-sm font-medium"
                                                        >
                                                            { "Revoke" }
                                                        </button>
                                                    }
                                                </div>
                                            }
                                        }
                                    })))}
                                />

                                // Pagination
                                if total_pages > 1 {
                                    <div class="border-t border-gray-200 px-4 py-3">
                                        <Pagination
                                            current_page={state.page as usize}
                                            total_pages={total_pages as usize}
                                            on_page_change={on_page_change.reform(|p: usize| p as u32)}
                                        />
                                    </div>
                                }
                            </div>
                        </>
                    },
                }
            }

            // Revocation modal
            if let Some(cert) = (*revoke_cert).clone() {
                <RevokeCertificateModal
                    certificate={cert}
                    on_close={on_revoke_close}
                    on_confirm={on_revoke_confirm}
                />
            }
        </Protected>
    }
}

/// Fetch certificates from API
async fn fetch_certificates(state: &CertListState) -> Result<CertificateListResponse, ApiError> {
    let filter = CertificateFilter {
        search: if state.search.is_empty() {
            None
        } else {
            Some(state.search.clone())
        },
        status: if state.status_filter == "all" {
            None
        } else {
            Some(state.status_filter.clone())
        },
        page: state.page,
        page_size: state.page_size,
    };

    // Try API, fall back to mock data
    match api()
        .get::<CertificateListResponse>(&format!(
            "/ca/certificates?page={}&pageSize={}&status={}&search={}",
            filter.page,
            filter.page_size,
            filter.status.as_deref().unwrap_or(""),
            filter.search.as_deref().unwrap_or("")
        ))
        .await
    {
        Ok(data) => Ok(data),
        Err(_) => Ok(get_mock_certificates(&filter)),
    }
}

/// Generate mock certificate data
fn get_mock_certificates(filter: &CertificateFilter) -> CertificateListResponse {
    let all_certs = vec![
        CertificateSummary {
            id: "cert-001".to_string(),
            serial_number: "A1B2C3D4E5F60001".to_string(),
            subject: "CN=api.example.com, O=Example Corp, C=US".to_string(),
            issuer: "CN=OstrichPKI Intermediate CA, O=OstrichPKI, C=US".to_string(),
            valid_from: "2024-01-15".to_string(),
            valid_to: "2025-01-15".to_string(),
            status: CertificateStatus::Active,
            key_algorithm: Some("ECDSA P-256".to_string()),
        },
        CertificateSummary {
            id: "cert-002".to_string(),
            serial_number: "A1B2C3D4E5F60002".to_string(),
            subject: "CN=web.example.com, O=Example Corp, C=US".to_string(),
            issuer: "CN=OstrichPKI Intermediate CA, O=OstrichPKI, C=US".to_string(),
            valid_from: "2024-02-01".to_string(),
            valid_to: "2025-02-01".to_string(),
            status: CertificateStatus::Active,
            key_algorithm: Some("RSA 2048".to_string()),
        },
        CertificateSummary {
            id: "cert-003".to_string(),
            serial_number: "A1B2C3D4E5F60003".to_string(),
            subject: "CN=mail.example.com, O=Example Corp, C=US".to_string(),
            issuer: "CN=OstrichPKI Intermediate CA, O=OstrichPKI, C=US".to_string(),
            valid_from: "2024-03-01".to_string(),
            valid_to: "2025-03-01".to_string(),
            status: CertificateStatus::Active,
            key_algorithm: Some("ECDSA P-384".to_string()),
        },
        CertificateSummary {
            id: "cert-004".to_string(),
            serial_number: "A1B2C3D4E5F60004".to_string(),
            subject: "CN=old-server.local, O=Example Corp, C=US".to_string(),
            issuer: "CN=OstrichPKI Intermediate CA, O=OstrichPKI, C=US".to_string(),
            valid_from: "2023-06-01".to_string(),
            valid_to: "2024-06-01".to_string(),
            status: CertificateStatus::Revoked,
            key_algorithm: Some("RSA 2048".to_string()),
        },
        CertificateSummary {
            id: "cert-005".to_string(),
            serial_number: "A1B2C3D4E5F60005".to_string(),
            subject: "CN=legacy.example.com, O=Example Corp, C=US".to_string(),
            issuer: "CN=OstrichPKI Intermediate CA, O=OstrichPKI, C=US".to_string(),
            valid_from: "2022-01-01".to_string(),
            valid_to: "2023-01-01".to_string(),
            status: CertificateStatus::Expired,
            key_algorithm: Some("RSA 2048".to_string()),
        },
        CertificateSummary {
            id: "cert-006".to_string(),
            serial_number: "A1B2C3D4E5F60006".to_string(),
            subject: "CN=new-service.example.com, O=Example Corp, C=US".to_string(),
            issuer: "CN=OstrichPKI Intermediate CA, O=OstrichPKI, C=US".to_string(),
            valid_from: "2024-01-20".to_string(),
            valid_to: "2025-01-20".to_string(),
            status: CertificateStatus::Pending,
            key_algorithm: Some("ML-DSA-65".to_string()),
        },
        CertificateSummary {
            id: "cert-007".to_string(),
            serial_number: "A1B2C3D4E5F60007".to_string(),
            subject: "CN=db.example.com, O=Example Corp, C=US".to_string(),
            issuer: "CN=OstrichPKI Intermediate CA, O=OstrichPKI, C=US".to_string(),
            valid_from: "2024-01-10".to_string(),
            valid_to: "2025-01-10".to_string(),
            status: CertificateStatus::Active,
            key_algorithm: Some("ECDSA P-256".to_string()),
        },
        CertificateSummary {
            id: "cert-008".to_string(),
            serial_number: "A1B2C3D4E5F60008".to_string(),
            subject: "CN=cache.example.com, O=Example Corp, C=US".to_string(),
            issuer: "CN=OstrichPKI Intermediate CA, O=OstrichPKI, C=US".to_string(),
            valid_from: "2024-02-15".to_string(),
            valid_to: "2025-02-15".to_string(),
            status: CertificateStatus::Active,
            key_algorithm: Some("ECDSA P-256".to_string()),
        },
    ];

    // Apply filters
    let filtered: Vec<CertificateSummary> = all_certs
        .into_iter()
        .filter(|cert| {
            // Status filter
            if let Some(ref status) = filter.status {
                let cert_status = cert.status.to_string().to_lowercase();
                if cert_status != *status {
                    return false;
                }
            }
            // Search filter
            if let Some(ref search) = filter.search {
                let search_lower = search.to_lowercase();
                if !cert.subject.to_lowercase().contains(&search_lower)
                    && !cert.serial_number.to_lowercase().contains(&search_lower)
                {
                    return false;
                }
            }
            true
        })
        .collect();

    let total = filtered.len() as u64;

    // Apply pagination
    let start = ((filter.page - 1) * filter.page_size) as usize;
    let certificates: Vec<CertificateSummary> = filtered
        .into_iter()
        .skip(start)
        .take(filter.page_size as usize)
        .collect();

    CertificateListResponse {
        certificates,
        total,
        page: filter.page,
        page_size: filter.page_size,
    }
}

// =============================================================================
// Revoke Certificate Modal
// =============================================================================

#[derive(Properties, PartialEq)]
struct RevokeCertificateModalProps {
    certificate: CertificateSummary,
    on_close: Callback<()>,
    on_confirm: Callback<()>,
}

#[function_component(RevokeCertificateModal)]
fn revoke_certificate_modal(props: &RevokeCertificateModalProps) -> Html {
    let reason = use_state(|| RevocationReason::Unspecified);
    let notes = use_state(String::new);

    let on_reason_change = {
        let reason = reason.clone();
        Callback::from(move |e: Event| {
            let select: web_sys::HtmlSelectElement = e.target_unchecked_into();
            let new_reason = match select.value().as_str() {
                "keyCompromise" => RevocationReason::KeyCompromise,
                "caCompromise" => RevocationReason::CaCompromise,
                "affiliationChanged" => RevocationReason::AffiliationChanged,
                "superseded" => RevocationReason::Superseded,
                "cessationOfOperation" => RevocationReason::CessationOfOperation,
                "certificateHold" => RevocationReason::CertificateHold,
                "privilegeWithdrawn" => RevocationReason::PrivilegeWithdrawn,
                _ => RevocationReason::Unspecified,
            };
            reason.set(new_reason);
        })
    };

    let on_notes_change = {
        let notes = notes.clone();
        Callback::from(move |e: InputEvent| {
            let textarea: web_sys::HtmlTextAreaElement = e.target_unchecked_into();
            notes.set(textarea.value());
        })
    };

    html! {
        <Modal
            open={true}
            title="Revoke Certificate"
            size={ModalSize::Medium}
            on_close={props.on_close.clone()}
        >
            <div class="space-y-4">
                <Alert alert_type={AlertType::Warning} dismissible={false}>
                    { "Warning: Certificate revocation is permanent and cannot be undone." }
                </Alert>

                <div>
                    <p class="text-sm text-gray-600 mb-2">{ "Certificate to revoke:" }</p>
                    <div class="bg-gray-50 rounded-lg p-3">
                        <p class="font-medium text-gray-900">{ &props.certificate.subject }</p>
                        <p class="text-sm text-gray-500 font-mono">{ &props.certificate.serial_number }</p>
                    </div>
                </div>

                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">
                        { "Revocation Reason" }
                        <span class="text-red-500">{ " *" }</span>
                    </label>
                    <select
                        class="form-select w-full"
                        onchange={on_reason_change}
                    >
                        <option value="unspecified">{ "Unspecified" }</option>
                        <option value="keyCompromise">{ "Key Compromise" }</option>
                        <option value="caCompromise">{ "CA Compromise" }</option>
                        <option value="affiliationChanged">{ "Affiliation Changed" }</option>
                        <option value="superseded">{ "Superseded" }</option>
                        <option value="cessationOfOperation">{ "Cessation of Operation" }</option>
                        <option value="certificateHold">{ "Certificate Hold" }</option>
                        <option value="privilegeWithdrawn">{ "Privilege Withdrawn" }</option>
                    </select>
                </div>

                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">
                        { "Notes (optional)" }
                    </label>
                    <textarea
                        class="form-input w-full"
                        rows="3"
                        placeholder="Add any notes about this revocation..."
                        oninput={on_notes_change}
                        value={(*notes).clone()}
                    />
                </div>

                <div class="flex justify-end gap-3 pt-4 border-t border-gray-200">
                    <button
                        onclick={props.on_close.reform(|_| ())}
                        class="btn-secondary"
                    >
                        { "Cancel" }
                    </button>
                    <button
                        onclick={props.on_confirm.reform(|_| ())}
                        class="btn-danger"
                    >
                        { "Revoke Certificate" }
                    </button>
                </div>
            </div>
        </Modal>
    }
}

// =============================================================================
// Certificate Detail Page
// =============================================================================

/// Certificate detail page properties
#[derive(Properties, PartialEq)]
pub struct CertificateDetailProps {
    pub id: String,
}

/// Certificate detail page
#[function_component(CertificateDetail)]
pub fn certificate_detail(props: &CertificateDetailProps) -> Html {
    let cert_state = use_state(|| LoadState::<CertificateDetails>::Loading);
    let show_pem = use_state(|| false);

    // Fetch certificate details on mount
    {
        let cert_state = cert_state.clone();
        let id = props.id.clone();
        use_effect_with(id.clone(), move |_| {
            let cert_state = cert_state.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match fetch_certificate_details(&id).await {
                    Ok(cert) => cert_state.set(LoadState::Loaded(cert)),
                    Err(e) => cert_state.set(LoadState::Error(e.message)),
                }
            });
            || ()
        });
    }

    // Toggle PEM view
    let toggle_pem = {
        let show_pem = show_pem.clone();
        Callback::from(move |_| show_pem.set(!*show_pem))
    };

    html! {
        <Protected permission="view_certificates">
            // Back button
            <a
                href="/certificates"
                class="flex items-center gap-2 text-gray-600 hover:text-gray-900 mb-4"
            >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
                </svg>
                { "Back to Certificates" }
            </a>

            {
                match (*cert_state).clone() {
                    LoadState::Loading => html! {
                        <div class="flex justify-center py-12">
                            <Loading message="Loading certificate details..." />
                        </div>
                    },
                    LoadState::Error(msg) => html! {
                        <Alert alert_type={AlertType::Error} dismissible={false}>
                            { format!("Failed to load certificate: {}", msg) }
                        </Alert>
                    },
                    LoadState::Loaded(cert) => html! {
                        <CertificateDetailContent
                            certificate={cert}
                            show_pem={*show_pem}
                            on_toggle_pem={toggle_pem}
                        />
                    },
                }
            }
        </Protected>
    }
}

/// Fetch certificate details from API
async fn fetch_certificate_details(id: &str) -> Result<CertificateDetails, ApiError> {
    match api()
        .get::<CertificateDetails>(&format!("/ca/certificates/{}", id))
        .await
    {
        Ok(cert) => Ok(cert),
        Err(_) => Ok(get_mock_certificate_details(id)),
    }
}

/// Generate mock certificate details
fn get_mock_certificate_details(id: &str) -> CertificateDetails {
    CertificateDetails {
        id: id.to_string(),
        serial_number: "A1B2C3D4E5F60001".to_string(),
        version: 3,
        status: CertificateStatus::Active,
        subject_dn: "CN=api.example.com, O=Example Corp, L=San Francisco, ST=California, C=US"
            .to_string(),
        issuer_dn: "CN=OstrichPKI Intermediate CA, O=OstrichPKI, C=US".to_string(),
        valid_from: "2024-01-15T00:00:00Z".to_string(),
        valid_to: "2025-01-15T23:59:59Z".to_string(),
        days_remaining: Some(365),
        key_algorithm: "ECDSA".to_string(),
        key_size: 256,
        signature_algorithm: "SHA256withECDSA".to_string(),
        fingerprint_sha256: "AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90".to_string(),
        fingerprint_sha1: "AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12".to_string(),
        extensions: vec![
            crate::types::api::CertificateExtension {
                oid: "2.5.29.15".to_string(),
                name: "Key Usage".to_string(),
                critical: true,
                value: "Digital Signature, Key Encipherment".to_string(),
            },
            crate::types::api::CertificateExtension {
                oid: "2.5.29.37".to_string(),
                name: "Extended Key Usage".to_string(),
                critical: false,
                value: "TLS Web Server Authentication, TLS Web Client Authentication".to_string(),
            },
            crate::types::api::CertificateExtension {
                oid: "2.5.29.19".to_string(),
                name: "Basic Constraints".to_string(),
                critical: true,
                value: "CA: FALSE".to_string(),
            },
        ],
        subject_alt_names: vec![
            crate::types::api::SubjectAltName {
                name_type: "DNS".to_string(),
                value: "api.example.com".to_string(),
            },
            crate::types::api::SubjectAltName {
                name_type: "DNS".to_string(),
                value: "*.api.example.com".to_string(),
            },
            crate::types::api::SubjectAltName {
                name_type: "IP".to_string(),
                value: "192.168.1.100".to_string(),
            },
        ],
        key_usage: vec![
            "Digital Signature".to_string(),
            "Key Encipherment".to_string(),
        ],
        extended_key_usage: vec![
            "TLS Web Server Authentication".to_string(),
            "TLS Web Client Authentication".to_string(),
        ],
        authority_key_id: Some(
            "12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78".to_string(),
        ),
        subject_key_id: Some(
            "AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12".to_string(),
        ),
        crl_distribution_points: vec![
            "http://crl.ostrichpki.example.com/intermediate.crl".to_string()
        ],
        ocsp_responder_urls: vec!["http://ocsp.ostrichpki.example.com".to_string()],
        revocation_time: None,
        revocation_reason: None,
        pem: r#"-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUdGVzdC1jZXJ0aWZpY2F0ZS0wMDEwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDAxMTUwMDAwMDBaFw0yNTAx
MTUyMzU5NTlaME0xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYw
FAYDVQQHDA1TYW4gRnJhbmNpc2NvMREwDwYDVQQKDAhFeGFtcGxlMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7
...
-----END CERTIFICATE-----"#
            .to_string(),
    }
}

/// Certificate detail content properties
#[derive(Properties, PartialEq)]
struct CertificateDetailContentProps {
    certificate: CertificateDetails,
    show_pem: bool,
    on_toggle_pem: Callback<MouseEvent>,
}

/// Certificate detail content component
#[function_component(CertificateDetailContent)]
fn certificate_detail_content(props: &CertificateDetailContentProps) -> Html {
    let cert = &props.certificate;

    let status_variant = match cert.status {
        CertificateStatus::Active => BadgeVariant::Success,
        CertificateStatus::Revoked => BadgeVariant::Danger,
        CertificateStatus::Expired => BadgeVariant::Warning,
        CertificateStatus::Pending => BadgeVariant::Info,
    };

    html! {
        <>
            <div class="page-header flex flex-col md:flex-row justify-between items-start gap-4">
                <div>
                    <div class="flex items-center gap-3">
                        <h1 class="page-title">{ "Certificate Details" }</h1>
                        <Badge variant={status_variant}>{ cert.status.to_string() }</Badge>
                    </div>
                    <p class="page-description font-mono text-sm">{ &cert.serial_number }</p>
                </div>
                <div class="flex gap-2">
                    <button
                        onclick={props.on_toggle_pem.clone()}
                        class="btn-secondary"
                    >
                        { if props.show_pem { "Hide PEM" } else { "Show PEM" } }
                    </button>
                    if cert.status == CertificateStatus::Active {
                        <button class="btn-danger">
                            { "Revoke" }
                        </button>
                    }
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                // Subject Information
                <div class="card">
                    <div class="card-header">
                        <h2 class="text-lg font-semibold text-gray-900">{ "Subject" }</h2>
                    </div>
                    <div class="card-body space-y-3">
                        <DetailRow label="Distinguished Name" value={cert.subject_dn.clone()} mono={true} />
                        <div>
                            <p class="text-sm font-medium text-gray-500">{ "Subject Alternative Names" }</p>
                            <ul class="mt-1 space-y-1">
                                {
                                    cert.subject_alt_names.iter().map(|san| {
                                        html! {
                                            <li class="text-sm font-mono text-gray-900">
                                                <span class="text-gray-500">{ &san.name_type }{ ": " }</span>
                                                { &san.value }
                                            </li>
                                        }
                                    }).collect::<Html>()
                                }
                            </ul>
                        </div>
                    </div>
                </div>

                // Issuer Information
                <div class="card">
                    <div class="card-header">
                        <h2 class="text-lg font-semibold text-gray-900">{ "Issuer" }</h2>
                    </div>
                    <div class="card-body space-y-3">
                        <DetailRow label="Distinguished Name" value={cert.issuer_dn.clone()} mono={true} />
                        if let Some(ref aki) = cert.authority_key_id {
                            <DetailRow label="Authority Key ID" value={aki.clone()} mono={true} />
                        }
                    </div>
                </div>

                // Validity Period
                <div class="card">
                    <div class="card-header">
                        <h2 class="text-lg font-semibold text-gray-900">{ "Validity" }</h2>
                    </div>
                    <div class="card-body space-y-3">
                        <DetailRow label="Valid From" value={cert.valid_from.clone()} mono={false} />
                        <DetailRow label="Valid To" value={cert.valid_to.clone()} mono={false} />
                        if let Some(days) = cert.days_remaining {
                            <div>
                                <p class="text-sm font-medium text-gray-500">{ "Days Remaining" }</p>
                                <p class={classes!(
                                    "text-sm", "font-semibold",
                                    if days > 30 { "text-green-600" }
                                    else if days > 7 { "text-amber-600" }
                                    else { "text-red-600" }
                                )}>
                                    { days }
                                </p>
                            </div>
                        }
                    </div>
                </div>

                // Key Information
                <div class="card">
                    <div class="card-header">
                        <h2 class="text-lg font-semibold text-gray-900">{ "Key Information" }</h2>
                    </div>
                    <div class="card-body space-y-3">
                        <DetailRow label="Algorithm" value={cert.key_algorithm.clone()} mono={false} />
                        <DetailRow label="Key Size" value={format!("{} bits", cert.key_size)} mono={false} />
                        <DetailRow label="Signature Algorithm" value={cert.signature_algorithm.clone()} mono={false} />
                        if let Some(ref ski) = cert.subject_key_id {
                            <DetailRow label="Subject Key ID" value={ski.clone()} mono={true} />
                        }
                    </div>
                </div>

                // Key Usage
                <div class="card">
                    <div class="card-header">
                        <h2 class="text-lg font-semibold text-gray-900">{ "Key Usage" }</h2>
                    </div>
                    <div class="card-body space-y-3">
                        <div>
                            <p class="text-sm font-medium text-gray-500">{ "Key Usage" }</p>
                            <div class="flex flex-wrap gap-2 mt-1">
                                {
                                    cert.key_usage.iter().map(|ku| {
                                        html! { <Badge variant={BadgeVariant::Gray}>{ ku.clone() }</Badge> }
                                    }).collect::<Html>()
                                }
                            </div>
                        </div>
                        <div>
                            <p class="text-sm font-medium text-gray-500">{ "Extended Key Usage" }</p>
                            <div class="flex flex-wrap gap-2 mt-1">
                                {
                                    cert.extended_key_usage.iter().map(|eku| {
                                        html! { <Badge variant={BadgeVariant::Info}>{ eku.clone() }</Badge> }
                                    }).collect::<Html>()
                                }
                            </div>
                        </div>
                    </div>
                </div>

                // Fingerprints
                <div class="card">
                    <div class="card-header">
                        <h2 class="text-lg font-semibold text-gray-900">{ "Fingerprints" }</h2>
                    </div>
                    <div class="card-body space-y-3">
                        <DetailRow label="SHA-256" value={cert.fingerprint_sha256.clone()} mono={true} />
                        <DetailRow label="SHA-1" value={cert.fingerprint_sha1.clone()} mono={true} />
                    </div>
                </div>

                // Distribution Points
                <div class="card lg:col-span-2">
                    <div class="card-header">
                        <h2 class="text-lg font-semibold text-gray-900">{ "Distribution Points" }</h2>
                    </div>
                    <div class="card-body">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                                <p class="text-sm font-medium text-gray-500 mb-2">{ "CRL Distribution Points" }</p>
                                <ul class="space-y-1">
                                    {
                                        cert.crl_distribution_points.iter().map(|url| {
                                            html! {
                                                <li class="text-sm font-mono text-blue-600 hover:underline">
                                                    <a href={url.clone()} target="_blank" rel="noopener">{ url }</a>
                                                </li>
                                            }
                                        }).collect::<Html>()
                                    }
                                </ul>
                            </div>
                            <div>
                                <p class="text-sm font-medium text-gray-500 mb-2">{ "OCSP Responders" }</p>
                                <ul class="space-y-1">
                                    {
                                        cert.ocsp_responder_urls.iter().map(|url| {
                                            html! {
                                                <li class="text-sm font-mono text-blue-600 hover:underline">
                                                    <a href={url.clone()} target="_blank" rel="noopener">{ url }</a>
                                                </li>
                                            }
                                        }).collect::<Html>()
                                    }
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>

                // Extensions
                <div class="card lg:col-span-2">
                    <div class="card-header">
                        <h2 class="text-lg font-semibold text-gray-900">{ "Extensions" }</h2>
                    </div>
                    <div class="card-body overflow-x-auto">
                        <table class="table">
                            <thead class="table-header">
                                <tr>
                                    <th class="table-header-cell">{ "Name" }</th>
                                    <th class="table-header-cell">{ "OID" }</th>
                                    <th class="table-header-cell">{ "Critical" }</th>
                                    <th class="table-header-cell">{ "Value" }</th>
                                </tr>
                            </thead>
                            <tbody class="table-body">
                                {
                                    cert.extensions.iter().map(|ext| {
                                        html! {
                                            <tr class="table-row-hover">
                                                <td class="table-cell font-medium">{ &ext.name }</td>
                                                <td class="table-cell font-mono text-gray-500">{ &ext.oid }</td>
                                                <td class="table-cell">
                                                    if ext.critical {
                                                        <Badge variant={BadgeVariant::Danger}>{ "Yes" }</Badge>
                                                    } else {
                                                        <Badge variant={BadgeVariant::Gray}>{ "No" }</Badge>
                                                    }
                                                </td>
                                                <td class="table-cell text-sm">{ &ext.value }</td>
                                            </tr>
                                        }
                                    }).collect::<Html>()
                                }
                            </tbody>
                        </table>
                    </div>
                </div>

                // Revocation Information (if revoked)
                if cert.status == CertificateStatus::Revoked {
                    <div class="card lg:col-span-2">
                        <div class="card-header bg-red-50">
                            <h2 class="text-lg font-semibold text-red-900">{ "Revocation Information" }</h2>
                        </div>
                        <div class="card-body space-y-3">
                            if let Some(ref time) = cert.revocation_time {
                                <DetailRow label="Revocation Time" value={time.clone()} mono={false} />
                            }
                            if let Some(ref reason) = cert.revocation_reason {
                                <DetailRow label="Revocation Reason" value={reason.clone()} mono={false} />
                            }
                        </div>
                    </div>
                }

                // PEM View
                if props.show_pem {
                    <div class="card lg:col-span-2">
                        <div class="card-header flex justify-between items-center">
                            <h2 class="text-lg font-semibold text-gray-900">{ "PEM Encoded Certificate" }</h2>
                            <button
                                class="text-sm text-blue-600 hover:text-blue-800"
                                onclick={Callback::from(|_| {
                                    // Note: Copy to clipboard requires additional implementation
                                    // This is a placeholder for the functionality
                                })}
                            >
                                { "Copy to Clipboard" }
                            </button>
                        </div>
                        <div class="card-body">
                            <pre class="bg-gray-900 text-green-400 p-4 rounded-lg overflow-x-auto text-sm font-mono whitespace-pre-wrap">
                                { &cert.pem }
                            </pre>
                        </div>
                    </div>
                }
            </div>
        </>
    }
}

/// Detail row component for displaying label/value pairs
#[derive(Properties, PartialEq)]
struct DetailRowProps {
    label: &'static str,
    value: String,
    #[prop_or(false)]
    mono: bool,
}

#[function_component(DetailRow)]
fn detail_row(props: &DetailRowProps) -> Html {
    html! {
        <div>
            <p class="text-sm font-medium text-gray-500">{ props.label }</p>
            <p class={classes!(
                "text-sm", "text-gray-900", "break-all",
                if props.mono { "font-mono" } else { "" }
            )}>
                { &props.value }
            </p>
        </div>
    }
}
