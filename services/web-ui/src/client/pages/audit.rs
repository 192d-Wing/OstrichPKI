//! Audit Log Viewer Page
//!
//! Real, filterable audit-log review backed by `GET /ca/api/v1/audit`, plus an
//! on-demand integrity check (`/audit/verify`) that recomputes the hash chain
//! and verifies each signed record against the CA public key.
//!
//! COMPLIANCE MAPPING:
//! - NIAP PP-CA: FAU_SAR.1 (Audit Review), FAU_STG.1.2 / FAU_STG.4 (integrity)
//! - NIST 800-53: AU-6 (Audit Review), AU-9 / AU-9(3) / AU-10 (integrity, non-repudiation)

use yew::prelude::*;

use crate::components::auth::Protected;
use crate::components::common::{Alert, AlertType, Badge, BadgeVariant, Loading, Pagination};
use crate::services::api::api;
use crate::types::api::{AuditEvent, AuditListResponse, AuditVerifyResponse};

const PAGE_SIZE: u32 = 25;

/// Event-type filter options: (label, exact backend value).
const EVENT_TYPES: &[(&str, &str)] = &[
    ("All Events", ""),
    ("Authentication", "authentication"),
    ("Authorization", "authorization"),
    ("Certificate Issuance", "certificate_issuance"),
    ("Certificate Revocation", "certificate_revocation"),
    ("CRL Generation", "crl_generation"),
    ("Key Generation", "key_generation"),
    ("Configuration Change", "configuration_change"),
    ("Access Violation", "access_violation"),
    ("Token Lifecycle", "token_lifecycle"),
    ("EST Protocol", "est_protocol"),
    ("ACME Protocol", "acme_protocol"),
];

#[derive(Clone, PartialEq, Default)]
struct Filters {
    event_type: String,
    actor: String,
    outcome: String,
}

/// Audit logs page
#[function_component(AuditLogs)]
pub fn audit_logs() -> Html {
    let events = use_state(Vec::<AuditEvent>::new);
    let total = use_state(|| 0u64);
    let page = use_state(|| 1u32);
    let filters = use_state(Filters::default);
    let error = use_state(|| None::<String>);
    let loading = use_state(|| true);
    let verify = use_state(|| None::<AuditVerifyResponse>);
    let verifying = use_state(|| false);

    // Fetch the page whenever the filters or page change.
    {
        let events = events.clone();
        let total = total.clone();
        let error = error.clone();
        let loading = loading.clone();
        let f = (*filters).clone();
        let pg = *page;
        use_effect_with((f, pg), move |(f, pg)| {
            let events = events.clone();
            let total = total.clone();
            let error = error.clone();
            let loading = loading.clone();
            let mut q = url::form_urlencoded::Serializer::new(String::new());
            q.append_pair("page", &pg.to_string());
            q.append_pair("pageSize", &PAGE_SIZE.to_string());
            if !f.event_type.is_empty() {
                q.append_pair("eventType", &f.event_type);
            }
            if !f.actor.trim().is_empty() {
                q.append_pair("actor", f.actor.trim());
            }
            if !f.outcome.is_empty() {
                q.append_pair("outcome", &f.outcome);
            }
            let query = q.finish();
            loading.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                match api()
                    .get::<AuditListResponse>(&format!("/ca/api/v1/audit?{query}"))
                    .await
                {
                    Ok(resp) => {
                        events.set(resp.events);
                        total.set(resp.total);
                        error.set(None);
                    }
                    Err(e) => error.set(Some(e.message)),
                }
                loading.set(false);
            });
            || ()
        });
    }

    let on_event_type = {
        let filters = filters.clone();
        let page = page.clone();
        Callback::from(move |e: Event| {
            let sel: web_sys::HtmlSelectElement = e.target_unchecked_into();
            let mut nf = (*filters).clone();
            nf.event_type = sel.value();
            filters.set(nf);
            page.set(1);
        })
    };
    let on_actor = {
        let filters = filters.clone();
        let page = page.clone();
        Callback::from(move |e: InputEvent| {
            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
            let mut nf = (*filters).clone();
            nf.actor = input.value();
            filters.set(nf);
            page.set(1);
        })
    };
    let on_outcome = {
        let filters = filters.clone();
        let page = page.clone();
        Callback::from(move |e: Event| {
            let sel: web_sys::HtmlSelectElement = e.target_unchecked_into();
            let mut nf = (*filters).clone();
            nf.outcome = sel.value();
            filters.set(nf);
            page.set(1);
        })
    };
    let on_page_change = {
        let page = page.clone();
        Callback::from(move |p: usize| page.set(p as u32))
    };
    let on_verify = {
        let verify = verify.clone();
        let verifying = verifying.clone();
        Callback::from(move |_| {
            let verify = verify.clone();
            let verifying = verifying.clone();
            verifying.set(true);
            wasm_bindgen_futures::spawn_local(async move {
                if let Ok(r) = api()
                    .get::<AuditVerifyResponse>("/ca/api/v1/audit/verify")
                    .await
                {
                    verify.set(Some(r));
                }
                verifying.set(false);
            });
        })
    };

    let total_pages = ((*total).max(1) as f64 / PAGE_SIZE as f64).ceil() as usize;

    html! {
        <Protected permission="read_audit_log">
            <div class="page-header flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <div>
                    <h1 class="page-title">{ "Audit Logs" }</h1>
                    <p class="page-description">{ "View, search, and verify the security audit trail" }</p>
                </div>
                <div class="flex items-center gap-3">
                    {
                        match (*verify).clone() {
                            Some(v) if v.intact => html! {
                                <Badge variant={BadgeVariant::Success} dot={true}>
                                    { format!("Integrity OK — {} records, {} signed", v.total_records, v.signed_records) }
                                </Badge>
                            },
                            Some(_) => html! {
                                <Badge variant={BadgeVariant::Danger} dot={true}>
                                    { "Integrity FAILED — tampering detected" }
                                </Badge>
                            },
                            None => html! {},
                        }
                    }
                    <button class="btn-secondary" onclick={on_verify} disabled={*verifying}>
                        { if *verifying { "Verifying…" } else { "Verify integrity" } }
                    </button>
                </div>
            </div>

            // Filters
            <div class="card mb-6">
                <div class="card-body">
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                            <label class="form-label">{ "Event Type" }</label>
                            <select class="form-select" onchange={on_event_type}>
                                { for EVENT_TYPES.iter().map(|(label, value)| html! {
                                    <option value={*value}>{ *label }</option>
                                }) }
                            </select>
                        </div>
                        <div>
                            <label class="form-label">{ "Actor" }</label>
                            <input type="text" class="form-input" placeholder="Username or service"
                                   value={(*filters).actor.clone()} oninput={on_actor} />
                        </div>
                        <div>
                            <label class="form-label">{ "Outcome" }</label>
                            <select class="form-select" onchange={on_outcome}>
                                <option value="">{ "All" }</option>
                                <option value="success">{ "Success" }</option>
                                <option value="failure">{ "Failure" }</option>
                                <option value="error">{ "Error" }</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>

            if let Some(msg) = (*error).clone() {
                <Alert alert_type={AlertType::Error} dismissible={false}>
                    { format!("Failed to load audit log: {msg}") }
                </Alert>
            } else if *loading {
                <div class="flex justify-center py-12"><Loading message="Loading audit records..." /></div>
            } else {
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
                                    <th class="table-header-cell">{ "Integrity" }</th>
                                </tr>
                            </thead>
                            <tbody class="table-body">
                                { for (*events).iter().map(render_row) }
                            </tbody>
                        </table>
                        if (*events).is_empty() {
                            <p class="text-sm text-gray-500 p-4">{ "No audit records match the current filters." }</p>
                        }
                    </div>
                    if total_pages > 1 {
                        <div class="p-4 border-t border-gray-100">
                            <Pagination
                                current_page={*page as usize}
                                total_pages={total_pages}
                                total_items={*total as usize}
                                page_size={PAGE_SIZE as usize}
                                show_page_size={false}
                                on_page_change={on_page_change}
                            />
                        </div>
                    }
                </div>
            }
        </Protected>
    }
}

fn render_row(e: &AuditEvent) -> Html {
    let outcome_variant = match e.outcome.as_str() {
        "success" => BadgeVariant::Success,
        "failure" => BadgeVariant::Danger,
        _ => BadgeVariant::Warning,
    };
    html! {
        <tr class="table-row-hover">
            <td class="table-cell text-gray-500 font-mono text-xs">{ &e.timestamp }</td>
            <td class="table-cell">{ &e.event_type }</td>
            <td class="table-cell font-medium text-gray-900">{ &e.actor }</td>
            <td class="table-cell text-gray-600">{ &e.target }</td>
            <td class="table-cell">{ &e.action }</td>
            <td class="table-cell"><Badge variant={outcome_variant}>{ &e.outcome }</Badge></td>
            <td class="table-cell">
                {
                    if e.signed {
                        html! { <Badge variant={BadgeVariant::Success}>{ "signed" }</Badge> }
                    } else {
                        html! { <Badge variant={BadgeVariant::Gray}>{ "chain" }</Badge> }
                    }
                }
            </td>
        </tr>
    }
}
