//! Certificate Revocation List (CRL) Management Page
//!
//! Generate and download full and delta CRLs (RFC 5280 §5). Generation requires
//! the `generate_crl` permission (OperationsStaff); the CRL itself is public
//! status data served at the CA's distribution point.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-17 (PKI certificate status), AC-3 (gated generation)
//! - NIAP PP-CA: FMT_SMF.1 (CRL generation/publication)
//! - RFC 5280 §5.2.4/§5.2.6 (delta CRLs)

use serde::Deserialize;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

use crate::components::auth::{Protected};
use crate::components::common::{Alert, AlertType};
use crate::services::api::api;
use crate::services::auth::use_auth;

#[derive(Clone, PartialEq, Deserialize)]
struct CrlResult {
    crl_number: u64,
    this_update: String,
    next_update: String,
    revoked_count: u64,
    pem_encoded: String,
}

#[function_component(Crl)]
pub fn crl() -> Html {
    html! {
        <Protected permission="view_crl">
            <CrlManager />
        </Protected>
    }
}

#[function_component(CrlManager)]
fn crl_manager() -> Html {
    let auth = use_auth();
    let can_generate = auth.has_permission("generate_crl");

    html! {
        <div class="max-w-4xl mx-auto">
            <div class="page-header">
                <h1 class="page-title">{ "Revocation Lists" }</h1>
                <p class="page-description">
                    { "Generate and download Certificate Revocation Lists (RFC 5280). \
                       The latest CRL is also published at the CA's distribution point." }
                </p>
            </div>

            if !can_generate {
                <div class="mb-4"><Alert alert_type={AlertType::Info} dismissible={false}>
                    { "You can download published CRLs. Generating a CRL requires the Operations role." }
                </Alert></div>
            }

            <div class="grid md:grid-cols-2 gap-6">
                <CrlCard
                    title="Full CRL"
                    description="A complete list of all revoked certificates."
                    endpoint="/ca/api/v1/crl"
                    download_name="crl.crl"
                    can_generate={can_generate}
                />
                <CrlCard
                    title="Delta CRL"
                    description="Only entries revoked since the last full CRL (RFC 5280 §5.2.4). Requires an existing full CRL."
                    endpoint="/ca/api/v1/crl/delta"
                    download_name="delta.crl"
                    can_generate={can_generate}
                />
            </div>
        </div>
    }
}

#[derive(Properties, PartialEq)]
struct CrlCardProps {
    title: &'static str,
    description: &'static str,
    /// Proxy path for this CRL (POST generates, GET downloads the DER).
    endpoint: &'static str,
    download_name: &'static str,
    can_generate: bool,
}

#[function_component(CrlCard)]
fn crl_card(props: &CrlCardProps) -> Html {
    let result = use_state(|| None::<CrlResult>);
    let error = use_state(|| None::<String>);
    let busy = use_state(|| false);

    let on_generate = {
        let endpoint = props.endpoint;
        let result = result.clone();
        let error = error.clone();
        let busy = busy.clone();
        Callback::from(move |_| {
            let result = result.clone();
            let error = error.clone();
            let busy = busy.clone();
            busy.set(true);
            error.set(None);
            spawn_local(async move {
                match api().post::<CrlResult, _>(endpoint, &serde_json::json!({})).await {
                    Ok(r) => result.set(Some(r)),
                    Err(e) => error.set(Some(if e.message.is_empty() {
                        format!("Generation failed (HTTP {})", e.status)
                    } else {
                        e.message
                    })),
                }
                busy.set(false);
            });
        })
    };

    // Same-origin GET through the proxy (the browser sends the session cookie),
    // prefixed with the API base.
    let download_href = format!("/api{}", props.endpoint);

    html! {
        <div class="card">
            <div class="card-body">
                <h2 class="text-lg font-semibold text-gray-900">{ props.title }</h2>
                <p class="text-sm text-gray-500 mt-1 mb-4">{ props.description }</p>

                if let Some(msg) = (*error).clone() {
                    <div class="mb-3"><Alert alert_type={AlertType::Error} dismissible={false}>{ msg }</Alert></div>
                }

                if let Some(r) = (*result).clone() {
                    <dl class="grid grid-cols-2 gap-1 text-sm mb-3">
                        <dt class="text-gray-500">{ "CRL number" }</dt><dd class="font-mono">{ r.crl_number }</dd>
                        <dt class="text-gray-500">{ "Revoked entries" }</dt><dd>{ r.revoked_count }</dd>
                        <dt class="text-gray-500">{ "This update" }</dt><dd>{ r.this_update }</dd>
                        <dt class="text-gray-500">{ "Next update" }</dt><dd>{ r.next_update }</dd>
                    </dl>
                }

                <div class="flex gap-3">
                    if props.can_generate {
                        <button onclick={on_generate} disabled={*busy} class="btn-primary disabled:opacity-60">
                            { if *busy { "Generating…" } else { "Generate" } }
                        </button>
                    }
                    <a href={download_href} download={props.download_name} class="btn-secondary">
                        { "Download latest (DER)" }
                    </a>
                </div>
            </div>
        </div>
    }
}
