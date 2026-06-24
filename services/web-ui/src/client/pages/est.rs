//! EST Enrollment Page (RFC 7030)
//!
//! Operator-facing EST console. It lets OperationsStaff/Administrators mint
//! single-use, time-limited bearer tokens for a device's initial enrollment, and
//! shows the EST endpoints, the trust anchors the server distributes, and live
//! reachability. Actual enrollment is performed by EST clients (devices), not the
//! browser — either over mTLS or with a token minted here.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-3 (access enforcement), CM-6 (configuration), SC-17 (PKI)
//! - NIAP PP-CA: FMT_SMF.1 / FMT_MTD.1 (enrollment-credential management)
//! - RFC 7030: EST (cacerts/csrattrs/simpleenroll/serverkeygen)

use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

use crate::components::auth::Protected;
use crate::components::common::{Alert, AlertType, Badge, BadgeVariant, CopyButton};
use crate::services::api::api;

#[function_component(Est)]
pub fn est() -> Html {
    // Gated on `generate_est_token`: held by OperationsStaff and Administrator,
    // the operators who manage device enrollment.
    html! {
        <Protected permission="generate_est_token">
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

            <EnrollmentTokenPanel />

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
                            { "Devices enroll over TLS, presenting either a TLS client certificate \
                               (mTLS) or a single-use bearer token minted above, and POSTing a CSR to " }
                            <code class="bg-gray-100 px-1 rounded">{ "/simpleenroll" }</code>
                            { "." }
                        </p>
                        <p class="text-sm text-gray-500 mt-2">
                            { "mTLS example: " }
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

/// Request body for minting an enrollment token (camelCase matches the EST API).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MintTokenRequest {
    identity: String,
    ttl_seconds: i64,
    /// Certificate profile the enrolled cert is issued under (EST allowlist).
    profile: String,
}

/// One-time response carrying the plaintext token. (The EST API also returns
/// `expiresInSeconds`; serde ignores fields we don't bind.)
#[derive(Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
struct MintTokenResponse {
    token: String,
    identity: String,
    expires_at: String,
}

/// A row of the enrollment-token inventory (metadata only; no secret).
#[derive(Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
struct TokenSummary {
    id: String,
    identity: String,
    created_by: String,
    created_at: String,
    expires_at: String,
    status: String, // live | used | revoked | expired
}

#[derive(Deserialize, Clone, PartialEq)]
struct TokenListResponse {
    tokens: Vec<TokenSummary>,
}

/// Operator panel: mint a single-use, time-limited EST enrollment token bound to
/// a device identity. The plaintext token is shown exactly once.
#[function_component(EnrollmentTokenPanel)]
fn enrollment_token_panel() -> Html {
    let identity = use_state(String::new);
    let ttl = use_state(|| 3600i64); // default 1 hour
    let profile = use_state(|| "tls_client".to_string()); // EST default
    let result = use_state(|| None::<MintTokenResponse>);
    let error = use_state(|| None::<String>);
    let busy = use_state(|| false);
    let tokens = use_state(Vec::<TokenSummary>::new);
    // Bumped after a mint or revoke to reload the outstanding-token list.
    let refresh = use_state(|| 0u32);

    // Load the outstanding-token list on mount and whenever `refresh` changes.
    {
        let tokens = tokens.clone();
        use_effect_with(*refresh, move |_| {
            let tokens = tokens.clone();
            spawn_local(async move {
                if let Ok(resp) = api()
                    .get::<TokenListResponse>("/est/api/v1/est/enrollment-tokens")
                    .await
                {
                    tokens.set(resp.tokens);
                }
            });
            || ()
        });
    }

    let on_revoke = {
        let refresh = refresh.clone();
        Callback::from(move |id: String| {
            let refresh = refresh.clone();
            spawn_local(async move {
                let _ = api()
                    .delete(&format!("/est/api/v1/est/enrollment-tokens/{id}"))
                    .await;
                refresh.set(*refresh + 1);
            });
        })
    };

    let on_identity = {
        let identity = identity.clone();
        Callback::from(move |e: InputEvent| {
            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
            identity.set(input.value());
        })
    };
    let on_ttl = {
        let ttl = ttl.clone();
        Callback::from(move |e: Event| {
            let sel: web_sys::HtmlSelectElement = e.target_unchecked_into();
            ttl.set(sel.value().parse().unwrap_or(3600));
        })
    };
    let on_profile = {
        let profile = profile.clone();
        Callback::from(move |e: Event| {
            let sel: web_sys::HtmlSelectElement = e.target_unchecked_into();
            profile.set(sel.value());
        })
    };
    // Select the token text on click so the operator can copy it easily.
    let select_all = Callback::from(|e: MouseEvent| {
        let input: web_sys::HtmlInputElement = e.target_unchecked_into();
        let _ = input.select();
    });

    let on_submit = {
        let identity = identity.clone();
        let ttl = ttl.clone();
        let profile = profile.clone();
        let result = result.clone();
        let error = error.clone();
        let busy = busy.clone();
        let refresh = refresh.clone();
        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            let id_val = (*identity).trim().to_string();
            if id_val.is_empty() {
                error.set(Some(
                    "Enter the device identity (certificate CN).".to_string(),
                ));
                return;
            }
            let ttl_val = *ttl;
            let profile_val = (*profile).clone();
            let result = result.clone();
            let error = error.clone();
            let busy = busy.clone();
            let refresh = refresh.clone();
            busy.set(true);
            error.set(None);
            result.set(None);
            spawn_local(async move {
                let req = MintTokenRequest {
                    identity: id_val,
                    ttl_seconds: ttl_val,
                    profile: profile_val,
                };
                match api()
                    .post::<MintTokenResponse, _>("/est/api/v1/est/enrollment-tokens", &req)
                    .await
                {
                    Ok(resp) => {
                        result.set(Some(resp));
                        refresh.set(*refresh + 1); // reload the outstanding-token list
                    }
                    Err(e) => error.set(Some(e.message)),
                }
                busy.set(false);
            });
        })
    };

    html! {
        <>
        <div class="card mb-6">
            <div class="card-body">
                <h2 class="text-lg font-semibold text-gray-900">{ "Generate enrollment token" }</h2>
                <p class="text-sm text-gray-500 mt-1 mb-4">
                    { "Mint a single-use, time-limited bearer token for a device's initial EST \
                       enrollment. The device must enroll with a CSR whose Common Name equals the \
                       identity below." }
                </p>

                <form onsubmit={on_submit} class="space-y-4">
                    <div class="grid sm:grid-cols-2 gap-4">
                        <div>
                            <label class="form-label">{ "Device identity (CN)" }</label>
                            <input type="text" class="form-input" placeholder="device-01.example.com"
                                   value={(*identity).clone()} oninput={on_identity} />
                        </div>
                        <div>
                            <label class="form-label">{ "Valid for" }</label>
                            <select class="form-select" onchange={on_ttl}>
                                <option value="900">{ "15 minutes" }</option>
                                <option value="3600" selected=true>{ "1 hour" }</option>
                                <option value="28800">{ "8 hours" }</option>
                                <option value="86400">{ "24 hours" }</option>
                            </select>
                        </div>
                        <div>
                            <label class="form-label">{ "Certificate profile" }</label>
                            <select class="form-select" onchange={on_profile}>
                                <option value="tls_client" selected=true>{ "TLS client (clientAuth)" }</option>
                                <option value="tls_server">{ "TLS server (serverAuth)" }</option>
                                <option value="tls_server_client">{ "TLS server + client (serverAuth + clientAuth)" }</option>
                            </select>
                            <p class="text-xs text-gray-500 mt-1">
                                { "Extended Key Usage of the issued certificate." }
                            </p>
                        </div>
                    </div>
                    <button type="submit" class="btn-primary" disabled={*busy}>
                        { if *busy { "Generating…" } else { "Generate token" } }
                    </button>
                </form>

                { if let Some(ref msg) = *error {
                    html! { <div class="mt-4"><Alert alert_type={AlertType::Error} dismissible={false}>{ msg.clone() }</Alert></div> }
                  } else { html! {} } }

                { if let Some(ref r) = *result {
                    let curl = format!(
                        "curl -k https://est.oopl.dev.mil/.well-known/est/simpleenroll \\\n  -H \"Authorization: Bearer {}\" \\\n  -H \"Content-Type: application/pkcs10\" \\\n  --data-binary @device.csr.b64",
                        r.token
                    );
                    html! {
                        <div class="mt-5 space-y-3">
                            <Alert alert_type={AlertType::Warning} dismissible={false}>
                                { "Copy this token now — it is shown only once and cannot be retrieved again." }
                            </Alert>
                            <div>
                                <label class="form-label">
                                    { format!("Token for {} (expires {})", r.identity, r.expires_at) }
                                </label>
                                <div class="relative">
                                    <input type="text" readonly=true class="form-input font-mono text-xs pr-20"
                                           value={r.token.clone()} onclick={select_all.clone()} />
                                    <div class="absolute inset-y-0 right-1.5 flex items-center">
                                        <CopyButton text={r.token.clone()} />
                                    </div>
                                </div>
                            </div>
                            <div>
                                <label class="form-label">{ "Enroll the device with:" }</label>
                                <div class="relative">
                                    <pre class="bg-gray-100 rounded p-3 pr-20 text-xs overflow-x-auto whitespace-pre">{ curl.clone() }</pre>
                                    <div class="absolute top-2 right-2">
                                        <CopyButton text={curl.clone()} />
                                    </div>
                                </div>
                            </div>
                        </div>
                    }
                  } else { html! {} } }
            </div>
        </div>

        <div class="card mb-6">
            <div class="card-body">
                <h2 class="text-lg font-semibold text-gray-900 mb-3">{ "Outstanding tokens" }</h2>
                { if tokens.is_empty() {
                    html! { <p class="text-sm text-gray-500">{ "No enrollment tokens minted yet." }</p> }
                  } else {
                    html! {
                        <table class="table">
                            <thead class="table-header">
                                <tr>
                                    <th class="table-header-cell">{ "Identity" }</th>
                                    <th class="table-header-cell">{ "Created by" }</th>
                                    <th class="table-header-cell">{ "Expires" }</th>
                                    <th class="table-header-cell">{ "Status" }</th>
                                    <th class="table-header-cell">{ "" }</th>
                                </tr>
                            </thead>
                            <tbody class="table-body">
                                { for tokens.iter().map(|t| {
                                    let badge = match t.status.as_str() {
                                        "live" => html! { <Badge variant={BadgeVariant::Success} dot={true}>{ "live" }</Badge> },
                                        "used" => html! { <Badge variant={BadgeVariant::Gray}>{ "used" }</Badge> },
                                        "revoked" => html! { <Badge variant={BadgeVariant::Danger}>{ "revoked" }</Badge> },
                                        _ => html! { <Badge variant={BadgeVariant::Warning}>{ "expired" }</Badge> },
                                    };
                                    let revoke = if t.status == "live" {
                                        let id = t.id.clone();
                                        let on_revoke = on_revoke.clone();
                                        let onclick = Callback::from(move |_| on_revoke.emit(id.clone()));
                                        html! { <button class="text-sm font-medium text-red-600 hover:text-red-700" {onclick}>{ "Revoke" }</button> }
                                    } else { html! {} };
                                    html! {
                                        <tr>
                                            <td class="table-cell font-mono">{ &t.identity }</td>
                                            <td class="table-cell text-gray-500">{ &t.created_by }</td>
                                            <td class="table-cell text-gray-500 text-xs font-mono">{ &t.expires_at }</td>
                                            <td class="table-cell">{ badge }</td>
                                            <td class="table-cell text-right">{ revoke }</td>
                                        </tr>
                                    }
                                }) }
                            </tbody>
                        </table>
                    }
                  } }
            </div>
        </div>
        </>
    }
}
