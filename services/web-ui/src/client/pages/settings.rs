//! Settings Page
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: CM-6 (Configuration Settings) - System configuration management
//! - NIST 800-53: CM-3 (Configuration Change Control) - Audit configuration changes
//! - NIAP PP-CA: FMT_SMF.1 (Security Management Functions)

use yew::prelude::*;

use crate::components::auth::Protected;
use crate::components::common::{Alert, AlertType, Badge, BadgeVariant};

/// Settings page
#[function_component(Settings)]
pub fn settings() -> Html {
    let active_tab = use_state(|| "general".to_string());

    let on_tab_change = {
        let active_tab = active_tab.clone();
        Callback::from(move |tab: String| {
            active_tab.set(tab);
        })
    };

    let tab_class = |tab: &str| {
        if *active_tab == tab {
            "border-primary-500 text-primary-600"
        } else {
            "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
        }
    };

    html! {
        <Protected permission="admin">
            <div class="page-header">
                <h1 class="page-title">{"Settings"}</h1>
                <p class="page-description">{"System configuration and preferences"}</p>
            </div>

            // Tabs navigation
            <div class="border-b border-gray-200 mb-6">
                <nav class="-mb-px flex space-x-8">
                    <button
                        type="button"
                        class={format!("whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm {}", tab_class("general"))}
                        onclick={let on_tab = on_tab_change.clone(); Callback::from(move |_| on_tab.emit("general".to_string()))}
                    >
                        {"General"}
                    </button>
                    <button
                        type="button"
                        class={format!("whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm {}", tab_class("security"))}
                        onclick={let on_tab = on_tab_change.clone(); Callback::from(move |_| on_tab.emit("security".to_string()))}
                    >
                        {"Security"}
                    </button>
                    <button
                        type="button"
                        class={format!("whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm {}", tab_class("certificates"))}
                        onclick={let on_tab = on_tab_change.clone(); Callback::from(move |_| on_tab.emit("certificates".to_string()))}
                    >
                        {"Certificates"}
                    </button>
                    <button
                        type="button"
                        class={format!("whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm {}", tab_class("notifications"))}
                        onclick={let on_tab = on_tab_change.clone(); Callback::from(move |_| on_tab.emit("notifications".to_string()))}
                    >
                        {"Notifications"}
                    </button>
                    <button
                        type="button"
                        class={format!("whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm {}", tab_class("integrations"))}
                        onclick={let on_tab = on_tab_change.clone(); Callback::from(move |_| on_tab.emit("integrations".to_string()))}
                    >
                        {"Integrations"}
                    </button>
                </nav>
            </div>

            // Tab content
            {match active_tab.as_str() {
                "general" => render_general_settings(),
                "security" => render_security_settings(),
                "certificates" => render_certificate_settings(),
                "notifications" => render_notification_settings(),
                "integrations" => render_integration_settings(),
                _ => render_general_settings(),
            }}
        </Protected>
    }
}

fn render_general_settings() -> Html {
    html! {
        <div class="space-y-6">
            // Organization Settings
            <div class="card">
                <div class="card-header">
                    <h3 class="text-lg font-medium text-gray-900">{"Organization"}</h3>
                    <p class="text-sm text-gray-500">{"Basic organization information"}</p>
                </div>
                <div class="card-body space-y-4">
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"Organization Name"}
                            </label>
                            <input
                                type="text"
                                class="form-input w-full"
                                value="OstrichPKI"
                            />
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"Organization Unit"}
                            </label>
                            <input
                                type="text"
                                class="form-input w-full"
                                value="PKI Operations"
                            />
                        </div>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            {"Contact Email"}
                        </label>
                        <input
                            type="email"
                            class="form-input w-full"
                            value="pki-admin@example.com"
                        />
                    </div>
                </div>
            </div>

            // Display Settings
            <div class="card">
                <div class="card-header">
                    <h3 class="text-lg font-medium text-gray-900">{"Display"}</h3>
                    <p class="text-sm text-gray-500">{"Customize the interface appearance"}</p>
                </div>
                <div class="card-body space-y-4">
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"Theme"}
                            </label>
                            <select class="form-select w-full">
                                <option value="light">{"Light"}</option>
                                <option value="dark">{"Dark"}</option>
                                <option value="system">{"System Default"}</option>
                            </select>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"Date Format"}
                            </label>
                            <select class="form-select w-full">
                                <option value="yyyy-mm-dd">{"YYYY-MM-DD"}</option>
                                <option value="mm/dd/yyyy">{"MM/DD/YYYY"}</option>
                                <option value="dd/mm/yyyy">{"DD/MM/YYYY"}</option>
                            </select>
                        </div>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            {"Timezone"}
                        </label>
                        <select class="form-select w-full">
                            <option value="UTC">{"UTC"}</option>
                            <option value="America/New_York">{"America/New_York (EST)"}</option>
                            <option value="America/Los_Angeles">{"America/Los_Angeles (PST)"}</option>
                            <option value="Europe/London">{"Europe/London (GMT)"}</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            {"Items Per Page"}
                        </label>
                        <select class="form-select w-48">
                            <option value="10">{"10"}</option>
                            <option value="25">{"25"}</option>
                            <option value="50">{"50"}</option>
                            <option value="100">{"100"}</option>
                        </select>
                    </div>
                </div>
            </div>

            // Save button
            <div class="flex justify-end">
                <button type="button" class="btn btn-primary">
                    {"Save Changes"}
                </button>
            </div>
        </div>
    }
}

fn render_security_settings() -> Html {
    html! {
        <div class="space-y-6">
            // Session Settings
            <div class="card">
                <div class="card-header">
                    <h3 class="text-lg font-medium text-gray-900">{"Session Management"}</h3>
                    <p class="text-sm text-gray-500">{"Configure session timeout and security settings"}</p>
                </div>
                <div class="card-body space-y-4">
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"Session Timeout (minutes)"}
                            </label>
                            <input
                                type="number"
                                class="form-input w-full"
                                value="15"
                                min="5"
                                max="60"
                            />
                            <p class="mt-1 text-xs text-gray-500">{"Session expires after inactivity"}</p>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"Maximum Session Duration (hours)"}
                            </label>
                            <input
                                type="number"
                                class="form-input w-full"
                                value="8"
                                min="1"
                                max="24"
                            />
                            <p class="mt-1 text-xs text-gray-500">{"Absolute session expiry"}</p>
                        </div>
                    </div>
                    <div class="flex items-center gap-2">
                        <input type="checkbox" class="form-checkbox" checked={true} />
                        <span class="text-sm text-gray-700">{"Require re-authentication for sensitive operations"}</span>
                    </div>
                </div>
            </div>

            // Password Policy
            <div class="card">
                <div class="card-header">
                    <h3 class="text-lg font-medium text-gray-900">{"Password Policy"}</h3>
                    <p class="text-sm text-gray-500">{"Configure password requirements"}</p>
                </div>
                <div class="card-body space-y-4">
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"Minimum Length"}
                            </label>
                            <input
                                type="number"
                                class="form-input w-full"
                                value="12"
                                min="8"
                                max="32"
                            />
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"Password Expiry (days)"}
                            </label>
                            <input
                                type="number"
                                class="form-input w-full"
                                value="90"
                                min="30"
                                max="365"
                            />
                        </div>
                    </div>
                    <div class="space-y-2">
                        <label class="flex items-center gap-2">
                            <input type="checkbox" class="form-checkbox" checked={true} />
                            <span class="text-sm text-gray-700">{"Require uppercase letters"}</span>
                        </label>
                        <label class="flex items-center gap-2">
                            <input type="checkbox" class="form-checkbox" checked={true} />
                            <span class="text-sm text-gray-700">{"Require lowercase letters"}</span>
                        </label>
                        <label class="flex items-center gap-2">
                            <input type="checkbox" class="form-checkbox" checked={true} />
                            <span class="text-sm text-gray-700">{"Require numbers"}</span>
                        </label>
                        <label class="flex items-center gap-2">
                            <input type="checkbox" class="form-checkbox" checked={true} />
                            <span class="text-sm text-gray-700">{"Require special characters"}</span>
                        </label>
                    </div>
                </div>
            </div>

            // MFA Settings
            <div class="card">
                <div class="card-header">
                    <h3 class="text-lg font-medium text-gray-900">{"Multi-Factor Authentication"}</h3>
                    <p class="text-sm text-gray-500">{"Configure MFA requirements"}</p>
                </div>
                <div class="card-body space-y-4">
                    <div class="flex items-center gap-2">
                        <input type="checkbox" class="form-checkbox" checked={true} />
                        <span class="text-sm text-gray-700">{"Require MFA for all users"}</span>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            {"Allowed MFA Methods"}
                        </label>
                        <div class="space-y-2">
                            <label class="flex items-center gap-2">
                                <input type="checkbox" class="form-checkbox" checked={true} />
                                <span class="text-sm text-gray-700">{"TOTP (Authenticator App)"}</span>
                            </label>
                            <label class="flex items-center gap-2">
                                <input type="checkbox" class="form-checkbox" checked={true} />
                                <span class="text-sm text-gray-700">{"Hardware Token (FIDO2/WebAuthn)"}</span>
                            </label>
                            <label class="flex items-center gap-2">
                                <input type="checkbox" class="form-checkbox" />
                                <span class="text-sm text-gray-700">{"SMS (Not recommended)"}</span>
                            </label>
                        </div>
                    </div>
                </div>
            </div>

            // Save button
            <div class="flex justify-end">
                <button type="button" class="btn btn-primary">
                    {"Save Changes"}
                </button>
            </div>
        </div>
    }
}

fn render_certificate_settings() -> Html {
    html! {
        <div class="space-y-6">
            // CA Configuration
            <div class="card">
                <div class="card-header">
                    <div class="flex items-center justify-between">
                        <div>
                            <h3 class="text-lg font-medium text-gray-900">{"Certificate Authority"}</h3>
                            <p class="text-sm text-gray-500">{"Root CA configuration"}</p>
                        </div>
                        <Badge text={"Active".to_string()} variant={BadgeVariant::Success} dot={true} />
                    </div>
                </div>
                <div class="card-body">
                    <dl class="grid grid-cols-2 gap-4">
                        <div>
                            <dt class="text-sm font-medium text-gray-500">{"Subject DN"}</dt>
                            <dd class="mt-1 text-sm text-gray-900 font-mono">{"CN=OstrichPKI Root CA, O=OstrichPKI, C=US"}</dd>
                        </div>
                        <div>
                            <dt class="text-sm font-medium text-gray-500">{"Serial Number"}</dt>
                            <dd class="mt-1 text-sm text-gray-900 font-mono">{"01:23:45:67:89:AB:CD:EF"}</dd>
                        </div>
                        <div>
                            <dt class="text-sm font-medium text-gray-500">{"Valid From"}</dt>
                            <dd class="mt-1 text-sm text-gray-900">{"2024-01-01 00:00:00 UTC"}</dd>
                        </div>
                        <div>
                            <dt class="text-sm font-medium text-gray-500">{"Valid Until"}</dt>
                            <dd class="mt-1 text-sm text-gray-900">{"2034-01-01 00:00:00 UTC"}</dd>
                        </div>
                        <div>
                            <dt class="text-sm font-medium text-gray-500">{"Key Algorithm"}</dt>
                            <dd class="mt-1 text-sm text-gray-900">{"RSA-4096"}</dd>
                        </div>
                        <div>
                            <dt class="text-sm font-medium text-gray-500">{"Signature Algorithm"}</dt>
                            <dd class="mt-1 text-sm text-gray-900">{"SHA-384 with RSA"}</dd>
                        </div>
                    </dl>
                </div>
            </div>

            // Default Certificate Profile
            <div class="card">
                <div class="card-header">
                    <h3 class="text-lg font-medium text-gray-900">{"Default Certificate Settings"}</h3>
                    <p class="text-sm text-gray-500">{"Default values for new certificates"}</p>
                </div>
                <div class="card-body space-y-4">
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"Default Validity Period"}
                            </label>
                            <select class="form-select w-full">
                                <option value="90d">{"90 Days"}</option>
                                <option value="1y">{"1 Year"}</option>
                                <option value="2y">{"2 Years"}</option>
                                <option value="3y">{"3 Years"}</option>
                            </select>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"Key Size (RSA)"}
                            </label>
                            <select class="form-select w-full">
                                <option value="2048">{"2048 bits"}</option>
                                <option value="3072">{"3072 bits"}</option>
                                <option value="4096">{"4096 bits"}</option>
                            </select>
                        </div>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            {"Allowed Key Types"}
                        </label>
                        <div class="space-y-2">
                            <label class="flex items-center gap-2">
                                <input type="checkbox" class="form-checkbox" checked={true} />
                                <span class="text-sm text-gray-700">{"RSA"}</span>
                            </label>
                            <label class="flex items-center gap-2">
                                <input type="checkbox" class="form-checkbox" checked={true} />
                                <span class="text-sm text-gray-700">{"ECDSA (P-256, P-384)"}</span>
                            </label>
                            <label class="flex items-center gap-2">
                                <input type="checkbox" class="form-checkbox" checked={true} />
                                <span class="text-sm text-gray-700">{"Ed25519"}</span>
                            </label>
                            <label class="flex items-center gap-2">
                                <input type="checkbox" class="form-checkbox" />
                                <span class="text-sm text-gray-700">{"ML-DSA (Post-Quantum)"}</span>
                            </label>
                        </div>
                    </div>
                </div>
            </div>

            // CRL/OCSP Settings
            <div class="card">
                <div class="card-header">
                    <h3 class="text-lg font-medium text-gray-900">{"Revocation Settings"}</h3>
                    <p class="text-sm text-gray-500">{"CRL and OCSP configuration"}</p>
                </div>
                <div class="card-body space-y-4">
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"CRL Update Interval (hours)"}
                            </label>
                            <input
                                type="number"
                                class="form-input w-full"
                                value="24"
                                min="1"
                                max="168"
                            />
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"OCSP Response Cache (minutes)"}
                            </label>
                            <input
                                type="number"
                                class="form-input w-full"
                                value="10"
                                min="1"
                                max="60"
                            />
                        </div>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            {"CRL Distribution Points"}
                        </label>
                        <input
                            type="text"
                            class="form-input w-full"
                            value="http://crl.example.com/ca.crl"
                        />
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            {"OCSP Responder URL"}
                        </label>
                        <input
                            type="text"
                            class="form-input w-full"
                            value="http://ocsp.example.com"
                        />
                    </div>
                </div>
            </div>

            // Save button
            <div class="flex justify-end">
                <button type="button" class="btn btn-primary">
                    {"Save Changes"}
                </button>
            </div>
        </div>
    }
}

fn render_notification_settings() -> Html {
    html! {
        <div class="space-y-6">
            // Email Notifications
            <div class="card">
                <div class="card-header">
                    <h3 class="text-lg font-medium text-gray-900">{"Email Notifications"}</h3>
                    <p class="text-sm text-gray-500">{"Configure email notification settings"}</p>
                </div>
                <div class="card-body space-y-4">
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"SMTP Server"}
                            </label>
                            <input
                                type="text"
                                class="form-input w-full"
                                placeholder="smtp.example.com"
                            />
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"SMTP Port"}
                            </label>
                            <input
                                type="number"
                                class="form-input w-full"
                                value="587"
                            />
                        </div>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            {"From Address"}
                        </label>
                        <input
                            type="email"
                            class="form-input w-full"
                            placeholder="pki-noreply@example.com"
                        />
                    </div>
                    <div class="flex items-center gap-2">
                        <input type="checkbox" class="form-checkbox" checked={true} />
                        <span class="text-sm text-gray-700">{"Use TLS"}</span>
                    </div>
                </div>
            </div>

            // Notification Events
            <div class="card">
                <div class="card-header">
                    <h3 class="text-lg font-medium text-gray-900">{"Notification Events"}</h3>
                    <p class="text-sm text-gray-500">{"Select which events trigger notifications"}</p>
                </div>
                <div class="card-body">
                    <div class="space-y-4">
                        <div class="flex items-center justify-between">
                            <div>
                                <span class="text-sm font-medium text-gray-700">{"Certificate Expiry Warning"}</span>
                                <p class="text-xs text-gray-500">{"Notify when certificates are about to expire"}</p>
                            </div>
                            <input type="checkbox" class="form-checkbox" checked={true} />
                        </div>
                        <div class="flex items-center justify-between">
                            <div>
                                <span class="text-sm font-medium text-gray-700">{"Certificate Issuance"}</span>
                                <p class="text-xs text-gray-500">{"Notify when new certificates are issued"}</p>
                            </div>
                            <input type="checkbox" class="form-checkbox" checked={true} />
                        </div>
                        <div class="flex items-center justify-between">
                            <div>
                                <span class="text-sm font-medium text-gray-700">{"Certificate Revocation"}</span>
                                <p class="text-xs text-gray-500">{"Notify when certificates are revoked"}</p>
                            </div>
                            <input type="checkbox" class="form-checkbox" checked={true} />
                        </div>
                        <div class="flex items-center justify-between">
                            <div>
                                <span class="text-sm font-medium text-gray-700">{"Pending Approvals"}</span>
                                <p class="text-xs text-gray-500">{"Notify approvers of pending requests"}</p>
                            </div>
                            <input type="checkbox" class="form-checkbox" checked={true} />
                        </div>
                        <div class="flex items-center justify-between">
                            <div>
                                <span class="text-sm font-medium text-gray-700">{"Security Alerts"}</span>
                                <p class="text-xs text-gray-500">{"Notify on security events (failed logins, etc.)"}</p>
                            </div>
                            <input type="checkbox" class="form-checkbox" checked={true} />
                        </div>
                    </div>
                </div>
            </div>

            // Expiry Warning Settings
            <div class="card">
                <div class="card-header">
                    <h3 class="text-lg font-medium text-gray-900">{"Expiry Warnings"}</h3>
                    <p class="text-sm text-gray-500">{"Configure certificate expiry warning thresholds"}</p>
                </div>
                <div class="card-body space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            {"Warning Thresholds (days before expiry)"}
                        </label>
                        <div class="flex gap-2">
                            <input type="number" class="form-input w-20" value="90" />
                            <input type="number" class="form-input w-20" value="60" />
                            <input type="number" class="form-input w-20" value="30" />
                            <input type="number" class="form-input w-20" value="7" />
                        </div>
                        <p class="mt-1 text-xs text-gray-500">{"Notifications sent at each threshold"}</p>
                    </div>
                </div>
            </div>

            // Save button
            <div class="flex justify-end">
                <button type="button" class="btn btn-primary">
                    {"Save Changes"}
                </button>
            </div>
        </div>
    }
}

fn render_integration_settings() -> Html {
    html! {
        <div class="space-y-6">
            // ACME Configuration
            <div class="card">
                <div class="card-header">
                    <div class="flex items-center justify-between">
                        <div>
                            <h3 class="text-lg font-medium text-gray-900">{"ACME Protocol"}</h3>
                            <p class="text-sm text-gray-500">{"Automatic Certificate Management Environment"}</p>
                        </div>
                        <Badge text={"Enabled".to_string()} variant={BadgeVariant::Success} dot={true} />
                    </div>
                </div>
                <div class="card-body space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            {"ACME Directory URL"}
                        </label>
                        <input
                            type="text"
                            class="form-input w-full bg-gray-50"
                            value="https://acme.example.com/directory"
                            readonly={true}
                        />
                    </div>
                    <div class="flex items-center gap-2">
                        <input type="checkbox" class="form-checkbox" checked={true} />
                        <span class="text-sm text-gray-700">{"Enable ACME endpoint"}</span>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            {"Allowed Challenge Types"}
                        </label>
                        <div class="space-y-2">
                            <label class="flex items-center gap-2">
                                <input type="checkbox" class="form-checkbox" checked={true} />
                                <span class="text-sm text-gray-700">{"HTTP-01"}</span>
                            </label>
                            <label class="flex items-center gap-2">
                                <input type="checkbox" class="form-checkbox" checked={true} />
                                <span class="text-sm text-gray-700">{"DNS-01"}</span>
                            </label>
                            <label class="flex items-center gap-2">
                                <input type="checkbox" class="form-checkbox" checked={true} />
                                <span class="text-sm text-gray-700">{"TLS-ALPN-01"}</span>
                            </label>
                        </div>
                    </div>
                </div>
            </div>

            // LDAP/AD Integration
            <div class="card">
                <div class="card-header">
                    <div class="flex items-center justify-between">
                        <div>
                            <h3 class="text-lg font-medium text-gray-900">{"LDAP/Active Directory"}</h3>
                            <p class="text-sm text-gray-500">{"Directory service integration"}</p>
                        </div>
                        <Badge text={"Not Configured".to_string()} variant={BadgeVariant::Default} />
                    </div>
                </div>
                <div class="card-body space-y-4">
                    <Alert
                        alert_type={AlertType::Info}
                        message={"LDAP integration enables automatic user provisioning and certificate publishing.".to_string()}
                    />
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"LDAP Server"}
                            </label>
                            <input
                                type="text"
                                class="form-input w-full"
                                placeholder="ldap.example.com"
                            />
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"LDAP Port"}
                            </label>
                            <input
                                type="number"
                                class="form-input w-full"
                                placeholder="636"
                            />
                        </div>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            {"Base DN"}
                        </label>
                        <input
                            type="text"
                            class="form-input w-full"
                            placeholder="DC=example,DC=com"
                        />
                    </div>
                    <div class="flex gap-2">
                        <button type="button" class="btn btn-secondary">
                            {"Test Connection"}
                        </button>
                    </div>
                </div>
            </div>

            // HSM Configuration
            <div class="card">
                <div class="card-header">
                    <div class="flex items-center justify-between">
                        <div>
                            <h3 class="text-lg font-medium text-gray-900">{"Hardware Security Module"}</h3>
                            <p class="text-sm text-gray-500">{"HSM integration for key protection"}</p>
                        </div>
                        <Badge text={"Connected".to_string()} variant={BadgeVariant::Success} dot={true} />
                    </div>
                </div>
                <div class="card-body">
                    <dl class="grid grid-cols-2 gap-4">
                        <div>
                            <dt class="text-sm font-medium text-gray-500">{"HSM Type"}</dt>
                            <dd class="mt-1 text-sm text-gray-900">{"PKCS#11"}</dd>
                        </div>
                        <div>
                            <dt class="text-sm font-medium text-gray-500">{"Library Path"}</dt>
                            <dd class="mt-1 text-sm text-gray-900 font-mono">{"/usr/lib/softhsm/libsofthsm2.so"}</dd>
                        </div>
                        <div>
                            <dt class="text-sm font-medium text-gray-500">{"Slot ID"}</dt>
                            <dd class="mt-1 text-sm text-gray-900">{"0"}</dd>
                        </div>
                        <div>
                            <dt class="text-sm font-medium text-gray-500">{"Status"}</dt>
                            <dd class="mt-1">
                                <Badge text={"Operational".to_string()} variant={BadgeVariant::Success} />
                            </dd>
                        </div>
                    </dl>
                </div>
            </div>

            // Save button
            <div class="flex justify-end">
                <button type="button" class="btn btn-primary">
                    {"Save Changes"}
                </button>
            </div>
        </div>
    }
}
