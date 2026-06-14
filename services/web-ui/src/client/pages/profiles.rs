//! Certificate Profiles Page (read-only catalog)
//!
//! Displays the CA's certificate profile catalog (GET /api/v1/profiles): the
//! issuance templates that constrain validity, key type, basic constraints,
//! and key-usage/EKU for each certificate class.
//!
//! Profiles are currently code-defined on the CA (no create/edit endpoint), so
//! this is a viewer. Editing would require a profile store + CRUD API.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: CM-2 (Baseline Configuration), CM-6 (Configuration Settings)
//! - NIAP PP-CA: FMT_SMF.1 (security management — view issuance policy)

use serde::Deserialize;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

use crate::components::auth::Protected;
use crate::components::common::{Alert, AlertType, Badge, BadgeVariant, Loading};
use crate::services::api::api;

#[derive(Clone, PartialEq, Deserialize)]
struct Profile {
    name: String,
    profile_type: String,
    #[serde(default)]
    description: String,
    validity_days: u32,
    key_type: String,
    algorithm: String,
    basic_constraints_ca: bool,
    basic_constraints_path_len: Option<u8>,
    subject_alt_name_required: bool,
    #[serde(default)]
    key_usages: Vec<String>,
    #[serde(default)]
    extended_key_usages: Vec<String>,
}

#[derive(Deserialize)]
struct ProfilesResponse {
    profiles: Vec<Profile>,
}

#[function_component(Profiles)]
pub fn profiles() -> Html {
    html! {
        <Protected permission="view_config">
            <ProfileCatalog />
        </Protected>
    }
}

#[function_component(ProfileCatalog)]
fn profile_catalog() -> Html {
    let profiles = use_state(|| None::<Vec<Profile>>);
    let error = use_state(|| None::<String>);

    {
        let profiles = profiles.clone();
        let error = error.clone();
        use_effect_with((), move |_| {
            spawn_local(async move {
                match api().get::<ProfilesResponse>("/ca/api/v1/profiles").await {
                    Ok(resp) => profiles.set(Some(resp.profiles)),
                    Err(e) => error.set(Some(if e.message.is_empty() {
                        format!("Failed to load profiles (HTTP {})", e.status)
                    } else {
                        e.message
                    })),
                }
            });
            || ()
        });
    }

    html! {
        <div class="max-w-5xl mx-auto">
            <div class="page-header">
                <h1 class="page-title">{ "Certificate Profiles" }</h1>
                <p class="page-description">
                    { "Issuance templates that constrain validity, key type, and extensions for each certificate class." }
                </p>
            </div>

            if let Some(msg) = (*error).clone() {
                <Alert alert_type={AlertType::Error} dismissible={false}>{ msg }</Alert>
            } else if let Some(list) = (*profiles).clone() {
                <div class="space-y-4">
                    { for list.iter().map(render_profile) }
                </div>
            } else {
                <Loading message={Some("Loading profiles...".to_string())} />
            }
        </div>
    }
}

fn render_profile(p: &Profile) -> Html {
    html! {
        <div class="card">
            <div class="card-body">
                <div class="flex items-start justify-between">
                    <div>
                        <h2 class="text-lg font-semibold text-gray-900">{ &p.name }</h2>
                        <p class="text-sm text-gray-500">{ &p.description }</p>
                    </div>
                    <div class="flex gap-2">
                        <Badge variant={BadgeVariant::Gray}>{ p.profile_type.clone() }</Badge>
                        if p.basic_constraints_ca {
                            <Badge variant={BadgeVariant::Warning}>{ "CA" }</Badge>
                        }
                    </div>
                </div>

                <dl class="grid grid-cols-2 md:grid-cols-4 gap-x-4 gap-y-2 text-sm mt-4">
                    <div><dt class="text-gray-500">{ "Validity" }</dt><dd>{ format!("{} days", p.validity_days) }</dd></div>
                    <div><dt class="text-gray-500">{ "Key type" }</dt><dd class="font-mono">{ &p.key_type }</dd></div>
                    <div><dt class="text-gray-500">{ "Signature" }</dt><dd class="font-mono">{ &p.algorithm }</dd></div>
                    <div>
                        <dt class="text-gray-500">{ "Path length" }</dt>
                        <dd>{ p.basic_constraints_path_len.map(|n| n.to_string()).unwrap_or_else(|| "—".into()) }</dd>
                    </div>
                    <div><dt class="text-gray-500">{ "SAN required" }</dt><dd>{ if p.subject_alt_name_required { "Yes" } else { "No" } }</dd></div>
                </dl>

                if !p.key_usages.is_empty() {
                    <div class="mt-3">
                        <p class="text-xs font-medium text-gray-500 mb-1">{ "Key Usage" }</p>
                        <div class="flex flex-wrap gap-1">
                            { for p.key_usages.iter().map(|k| html! {
                                <Badge variant={BadgeVariant::Info}>{ k.clone() }</Badge>
                            }) }
                        </div>
                    </div>
                }

                if !p.extended_key_usages.is_empty() {
                    <div class="mt-3">
                        <p class="text-xs font-medium text-gray-500 mb-1">{ "Extended Key Usage" }</p>
                        <div class="flex flex-wrap gap-1">
                            { for p.extended_key_usages.iter().map(|e| html! {
                                <Badge variant={BadgeVariant::Primary}>{ e.clone() }</Badge>
                            }) }
                        </div>
                    </div>
                }
            </div>
        </div>
    }
}
