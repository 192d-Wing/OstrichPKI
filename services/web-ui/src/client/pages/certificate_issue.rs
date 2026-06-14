//! Certificate Issuance Page
//!
//! Paste a PKCS#10 CSR (PEM), choose a profile, and issue an end-entity
//! certificate through the CA. The CA derives the subject, public key, and SANs
//! from the CSR and verifies proof-of-possession (RFC 2986).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-17 (PKI Certificates) - certificate issuance UI
//! - NIAP PP-CA: FMT_SMF.1 - security management (issuance)
//! - NIAP PP-CA: FDP_ACC.1 - gated on the `issue_certificates` permission

use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;
use web_sys::{HtmlSelectElement, HtmlTextAreaElement};
use yew::prelude::*;
use yew_router::prelude::*;

use crate::components::auth::Protected;
use crate::components::common::{Alert, AlertType};
use crate::router::Route;
use crate::services::api::api;

#[derive(Clone, PartialEq, Deserialize)]
struct Profile {
    name: String,
    profile_type: String,
}

#[derive(Deserialize)]
struct ProfilesResponse {
    profiles: Vec<Profile>,
}

#[derive(Serialize)]
struct IssueRequest {
    profile_name: String,
    csr_der: String,
}

#[derive(Clone, PartialEq, Deserialize)]
struct IssueResponse {
    certificate_id: String,
    serial_number: String,
    pem_encoded: String,
    not_before: String,
    not_after: String,
}

/// Strip the PEM armor from a CSR, leaving the base64 DER body (which is exactly
/// the `csr_der` the CA expects).
fn pem_to_csr_b64(pem: &str) -> String {
    pem.lines()
        .filter(|l| !l.contains("-----"))
        .flat_map(|l| l.split_whitespace())
        .collect()
}

#[function_component(CertificateIssue)]
pub fn certificate_issue() -> Html {
    html! {
        <Protected permission="issue_certificates">
            <IssueForm />
        </Protected>
    }
}

#[function_component(IssueForm)]
fn issue_form() -> Html {
    let profiles = use_state(Vec::<Profile>::new);
    let profile_name = use_state(String::new);
    let csr = use_state(String::new);
    let result = use_state(|| None::<IssueResponse>);
    let error = use_state(|| None::<String>);
    let submitting = use_state(|| false);

    // Load the profile catalog on mount.
    {
        let profiles = profiles.clone();
        let profile_name = profile_name.clone();
        use_effect_with((), move |_| {
            spawn_local(async move {
                if let Ok(resp) = api().get::<ProfilesResponse>("/ca/api/v1/profiles").await {
                    if let Some(first) = resp.profiles.first() {
                        profile_name.set(first.profile_type.clone());
                    }
                    profiles.set(resp.profiles);
                }
            });
            || ()
        });
    }

    let on_profile = {
        let profile_name = profile_name.clone();
        Callback::from(move |e: Event| {
            let sel: HtmlSelectElement = e.target_unchecked_into();
            profile_name.set(sel.value());
        })
    };
    let on_csr = {
        let csr = csr.clone();
        Callback::from(move |e: InputEvent| {
            let ta: HtmlTextAreaElement = e.target_unchecked_into();
            csr.set(ta.value());
        })
    };

    let on_submit = {
        let profile_name = profile_name.clone();
        let csr = csr.clone();
        let result = result.clone();
        let error = error.clone();
        let submitting = submitting.clone();
        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            let csr_b64 = pem_to_csr_b64(&csr);
            if csr_b64.is_empty() {
                error.set(Some("Paste a PEM-encoded certificate request (CSR).".into()));
                return;
            }
            let req = IssueRequest {
                profile_name: (*profile_name).clone(),
                csr_der: csr_b64,
            };
            let result = result.clone();
            let error = error.clone();
            let submitting = submitting.clone();
            submitting.set(true);
            error.set(None);
            result.set(None);
            spawn_local(async move {
                match api().post::<IssueResponse, _>("/ca/api/v1/certificates", &req).await {
                    Ok(resp) => result.set(Some(resp)),
                    Err(e) => error.set(Some(if e.message.is_empty() {
                        format!("Issuance failed (HTTP {})", e.status)
                    } else {
                        e.message
                    })),
                }
                submitting.set(false);
            });
        })
    };

    html! {
        <div class="max-w-3xl mx-auto">
            <div class="page-header flex items-center justify-between">
                <div>
                    <h1 class="page-title">{ "Issue Certificate" }</h1>
                    <p class="page-description">
                        { "Paste a PKCS#10 CSR and choose a profile. The CA derives the subject, public key, and SANs from the CSR." }
                    </p>
                </div>
                <Link<Route> to={Route::Certificates} classes="btn-secondary">{ "Back to list" }</Link<Route>>
            </div>

            if let Some(msg) = (*error).clone() {
                <div class="mb-4"><Alert alert_type={AlertType::Error} dismissible={false}>{ msg }</Alert></div>
            }

            if let Some(res) = (*result).clone() {
                { render_result(&res) }
            } else {
                <div class="card">
                    <div class="card-body">
                        <form onsubmit={on_submit}>
                            <label class="form-label">{ "Profile" }</label>
                            <select class="form-select mb-4" onchange={on_profile}>
                                { for profiles.iter().map(|p| html! {
                                    <option value={p.profile_type.clone()} selected={*profile_name == p.profile_type}>
                                        { format!("{} ({})", p.name, p.profile_type) }
                                    </option>
                                }) }
                            </select>

                            <label class="form-label">{ "Certificate Signing Request (PEM)" }</label>
                            <textarea
                                class="form-input font-mono text-xs mb-1"
                                rows="12"
                                placeholder="-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----"
                                value={(*csr).clone()}
                                oninput={on_csr}
                            />
                            <p class="text-xs text-gray-500 mb-4">
                                { "Generate one with: " }
                                <code class="bg-gray-100 px-1 rounded">{ "openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout key.pem -out req.csr -subj \"/CN=example.com\" -addext \"subjectAltName=DNS:example.com\"" }</code>
                            </p>

                            <button type="submit" disabled={*submitting} class="btn-primary disabled:opacity-60">
                                { if *submitting { "Issuing…" } else { "Issue Certificate" } }
                            </button>
                        </form>
                    </div>
                </div>
            }
        </div>
    }
}

fn render_result(res: &IssueResponse) -> Html {
    let href = format!(
        "data:application/x-pem-file;charset=utf-8,{}",
        js_sys::encode_uri_component(&res.pem_encoded)
    );
    html! {
        <div class="card">
            <div class="card-body">
                <div class="mb-4"><Alert alert_type={AlertType::Success} dismissible={false}>
                    { "Certificate issued successfully." }
                </Alert></div>

                <dl class="grid grid-cols-3 gap-2 text-sm mb-4">
                    <dt class="text-gray-500">{ "Certificate ID" }</dt>
                    <dd class="col-span-2 font-mono">{ &res.certificate_id }</dd>
                    <dt class="text-gray-500">{ "Serial" }</dt>
                    <dd class="col-span-2 font-mono break-all">{ &res.serial_number }</dd>
                    <dt class="text-gray-500">{ "Not before" }</dt>
                    <dd class="col-span-2">{ &res.not_before }</dd>
                    <dt class="text-gray-500">{ "Not after" }</dt>
                    <dd class="col-span-2">{ &res.not_after }</dd>
                </dl>

                <label class="form-label">{ "Certificate (PEM)" }</label>
                <textarea class="form-input font-mono text-xs mb-4" rows="12" readonly={true} value={res.pem_encoded.clone()} />

                <div class="flex gap-3">
                    <a href={href} download="certificate.pem" class="btn-primary">{ "Download PEM" }</a>
                    <Link<Route> to={Route::Certificates} classes="btn-secondary">{ "Done" }</Link<Route>>
                </div>
            </div>
        </div>
    }
}
