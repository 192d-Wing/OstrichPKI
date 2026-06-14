//! System Status / Settings Page
//!
//! Read-only system overview: CA identity, live health of each backend service,
//! and the running version. Policy/configuration (password policy, MFA, CRL
//! cadence, CA parameters) is managed today via service configuration/env, not
//! a runtime config API, so it is not editable here.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: CM-6 (Configuration Settings — observe effective config)
//! - NIST 800-53: SI-4 / SC-5 (service availability monitoring)
//! - NIAP PP-CA: FMT_SMF.1 (security management — system status)

use serde::Deserialize;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

use crate::components::auth::Protected;
use crate::components::common::{Alert, AlertType, Badge, BadgeVariant};
use crate::services::api::api;

#[derive(Clone, PartialEq, Deserialize)]
struct CaInfo {
    ca_id: String,
    ca_dn: String,
}

#[function_component(Settings)]
pub fn settings() -> Html {
    html! {
        <Protected permission="admin">
            <SystemOverview />
        </Protected>
    }
}

#[function_component(SystemOverview)]
fn system_overview() -> Html {
    html! {
        <div class="max-w-4xl mx-auto">
            <div class="page-header">
                <h1 class="page-title">{ "System" }</h1>
                <p class="page-description">
                    { "Certificate authority identity and live service status." }
                </p>
            </div>

            <CaCard />

            <div class="card mt-6">
                <div class="card-body">
                    <h2 class="text-lg font-semibold text-gray-900 mb-3">{ "Services" }</h2>
                    <div class="grid grid-cols-2 md:grid-cols-3 gap-3">
                        <ServiceHealth name="Certificate Authority" svc="ca" />
                        <ServiceHealth name="EST Enrollment" svc="est" />
                        <ServiceHealth name="ACME" svc="acme" />
                        <ServiceHealth name="OCSP Responder" svc="ocsp" />
                        <ServiceHealth name="SCMS" svc="scms" />
                        <ServiceHealth name="Key Recovery (KRA)" svc="kra" />
                    </div>
                </div>
            </div>

            <div class="mt-6">
                <Alert alert_type={AlertType::Info} dismissible={false}>
                    { "Policy and configuration (password policy, MFA, CRL cadence, CA parameters) \
                       are managed via service configuration and are read-only here." }
                </Alert>
            </div>

            <p class="text-xs text-gray-400 text-center mt-6">
                { format!("OstrichPKI Web UI v{}", env!("CARGO_PKG_VERSION")) }
            </p>
        </div>
    }
}

#[function_component(CaCard)]
fn ca_card() -> Html {
    let info = use_state(|| None::<CaInfo>);
    let error = use_state(|| false);

    {
        let info = info.clone();
        let error = error.clone();
        use_effect_with((), move |_| {
            spawn_local(async move {
                match api().get::<CaInfo>("/ca/api/v1/ca/info").await {
                    Ok(ci) => info.set(Some(ci)),
                    Err(_) => error.set(true),
                }
            });
            || ()
        });
    }

    html! {
        <div class="card">
            <div class="card-body">
                <h2 class="text-lg font-semibold text-gray-900 mb-3">{ "Certificate Authority" }</h2>
                if let Some(ci) = (*info).clone() {
                    <dl class="grid grid-cols-3 gap-2 text-sm">
                        <dt class="text-gray-500">{ "Subject" }</dt>
                        <dd class="col-span-2 font-mono">{ ci.ca_dn }</dd>
                        <dt class="text-gray-500">{ "CA ID" }</dt>
                        <dd class="col-span-2 font-mono break-all">{ ci.ca_id }</dd>
                    </dl>
                } else if *error {
                    <p class="text-sm text-red-600">{ "Unable to load CA information." }</p>
                } else {
                    <p class="text-sm text-gray-400">{ "Loading…" }</p>
                }
            </div>
        </div>
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Status {
    Checking,
    Up,
    Down,
}

#[derive(Properties, PartialEq)]
struct ServiceHealthProps {
    name: &'static str,
    /// Proxy service segment (ca, est, acme, …).
    svc: &'static str,
}

#[function_component(ServiceHealth)]
fn service_health(props: &ServiceHealthProps) -> Html {
    let status = use_state(|| Status::Checking);

    {
        let status = status.clone();
        let svc = props.svc;
        use_effect_with((), move |_| {
            spawn_local(async move {
                let up = api().get::<serde_json::Value>(&format!("/{svc}/health")).await.is_ok();
                status.set(if up { Status::Up } else { Status::Down });
            });
            || ()
        });
    }

    let badge = match *status {
        Status::Checking => html! { <Badge variant={BadgeVariant::Gray}>{ "…" }</Badge> },
        Status::Up => html! { <Badge variant={BadgeVariant::Success} dot={true}>{ "Up" }</Badge> },
        Status::Down => html! { <Badge variant={BadgeVariant::Danger} dot={true}>{ "Down" }</Badge> },
    };

    html! {
        <div class="flex items-center justify-between border border-gray-200 rounded px-3 py-2">
            <span class="text-sm text-gray-700">{ props.name }</span>
            { badge }
        </div>
    }
}
