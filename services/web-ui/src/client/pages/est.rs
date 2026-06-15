//! EST Enrollment Page (RFC 7030)
//!
//! EST is a machine-facing enrollment protocol: devices enroll over TLS with a
//! client certificate (mTLS, RFC 7030 §3.3). This page is therefore an
//! operator-facing *configuration/status* view — it shows the EST endpoints,
//! the trust anchors the server distributes, and live reachability — rather
//! than performing enrollment (which is done by EST clients, not a browser).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: CM-6 (Configuration Settings), SC-17 (PKI certificates)
//! - RFC 7030: EST (cacerts/csrattrs/simpleenroll/serverkeygen)

use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

use crate::components::auth::Protected;
use crate::components::common::{Badge, BadgeVariant};
use crate::services::api::api;

#[function_component(Est)]
pub fn est() -> Html {
    html! {
        <Protected permission="view_config">
            <EstStatus />
        </Protected>
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Health {
    Checking,
    Online,
    Offline,
}

#[function_component(EstStatus)]
fn est_status() -> Html {
    let health = use_state(|| Health::Checking);

    {
        let health = health.clone();
        use_effect_with((), move |_| {
            spawn_local(async move {
                // The health endpoint returns JSON; we only care that it answers.
                let ok = api().get::<serde_json::Value>("/est/health").await.is_ok();
                health.set(if ok { Health::Online } else { Health::Offline });
            });
            || ()
        });
    }

    let status_badge = match *health {
        Health::Checking => html! { <Badge variant={BadgeVariant::Gray}>{ "Checking…" }</Badge> },
        Health::Online => {
            html! { <Badge variant={BadgeVariant::Success} dot={true}>{ "Online" }</Badge> }
        }
        Health::Offline => {
            html! { <Badge variant={BadgeVariant::Danger} dot={true}>{ "Unreachable" }</Badge> }
        }
    };

    // Each EST operation: (method, path, auth, description)
    let ops = [
        (
            "GET",
            "/.well-known/est/cacerts",
            "Public",
            "Distribute the CA certificate chain (trust anchors), PKCS#7.",
        ),
        (
            "GET",
            "/.well-known/est/csrattrs",
            "Public",
            "CSR attributes the client should include (RFC 7030 §4.5).",
        ),
        (
            "POST",
            "/.well-known/est/simpleenroll",
            "mTLS",
            "Enroll: submit a CSR, receive a certificate (PKCS#7).",
        ),
        (
            "POST",
            "/.well-known/est/simplereenroll",
            "mTLS",
            "Re-enroll an existing certificate before expiry.",
        ),
        (
            "POST",
            "/.well-known/est/serverkeygen",
            "mTLS",
            "Server-side key generation: returns key + certificate.",
        ),
    ];

    html! {
        <div class="max-w-4xl mx-auto">
            <div class="page-header flex items-center justify-between">
                <div>
                    <h1 class="page-title">{ "EST Enrollment" }</h1>
                    <p class="page-description">
                        { "Enrollment over Secure Transport (RFC 7030). Clients enroll with a TLS client certificate." }
                    </p>
                </div>
                { status_badge }
            </div>

            <div class="card mb-6">
                <div class="card-body">
                    <h2 class="text-lg font-semibold text-gray-900 mb-3">{ "Endpoints" }</h2>
                    <table class="table">
                        <thead class="table-header">
                            <tr>
                                <th class="table-header-cell">{ "Method" }</th>
                                <th class="table-header-cell">{ "Path" }</th>
                                <th class="table-header-cell">{ "Auth" }</th>
                                <th class="table-header-cell">{ "Description" }</th>
                            </tr>
                        </thead>
                        <tbody class="table-body">
                            { for ops.iter().map(|(method, path, auth, desc)| {
                                let auth_badge = if *auth == "Public" {
                                    html! { <Badge variant={BadgeVariant::Gray}>{ *auth }</Badge> }
                                } else {
                                    html! { <Badge variant={BadgeVariant::Warning}>{ *auth }</Badge> }
                                };
                                html! {
                                    <tr>
                                        <td class="table-cell font-mono">{ *method }</td>
                                        <td class="table-cell font-mono text-xs">{ *path }</td>
                                        <td class="table-cell">{ auth_badge }</td>
                                        <td class="table-cell text-gray-500">{ *desc }</td>
                                    </tr>
                                }
                            }) }
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="grid md:grid-cols-2 gap-6">
                <div class="card">
                    <div class="card-body">
                        <h2 class="text-lg font-semibold text-gray-900">{ "Trust anchors" }</h2>
                        <p class="text-sm text-gray-500 mt-1 mb-4">
                            { "The CA certificate chain this EST server distributes to clients (PKCS#7)." }
                        </p>
                        <a href="/api/est/.well-known/est/cacerts" download="est-cacerts.p7c" class="btn-primary">
                            { "Download CA certificates" }
                        </a>
                    </div>
                </div>

                <div class="card">
                    <div class="card-body">
                        <h2 class="text-lg font-semibold text-gray-900">{ "Client enrollment" }</h2>
                        <p class="text-sm text-gray-500 mt-1">
                            { "Enrollment is performed by EST clients over mTLS, not from this console. \
                               A client presents a TLS client certificate and POSTs a CSR to " }
                            <code class="bg-gray-100 px-1 rounded">{ "/simpleenroll" }</code>
                            { "." }
                        </p>
                        <p class="text-sm text-gray-500 mt-2">
                            { "Example: " }
                            <code class="bg-gray-100 px-1 rounded text-xs">
                                { "curl --cert client.pem --key client.key https://est-host/.well-known/est/simpleenroll --data-binary @req.p10 -H 'Content-Type: application/pkcs10'" }
                            </code>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    }
}
