//! SCMS Token Management Page
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: IA-5 (Authenticator Management) - Token lifecycle management
//! - NIST 800-53: SC-12 (Cryptographic Key Establishment) - Token key management
//! - NIAP PP-CA: FCS_CKM.4 (Cryptographic Key Destruction)

use std::rc::Rc;
use yew::prelude::*;

use crate::components::auth::Protected;
use crate::components::common::{
    Alert, AlertType, Badge, BadgeVariant, Column, DataTable, Loading, Modal, ModalSize,
};

/// Token status
#[derive(Clone, PartialEq)]
pub enum TokenStatus {
    Active,
    Inactive,
    Locked,
    Revoked,
    Expired,
}

impl TokenStatus {
    fn as_str(&self) -> &'static str {
        match self {
            TokenStatus::Active => "Active",
            TokenStatus::Inactive => "Inactive",
            TokenStatus::Locked => "Locked",
            TokenStatus::Revoked => "Revoked",
            TokenStatus::Expired => "Expired",
        }
    }

    fn badge_variant(&self) -> BadgeVariant {
        match self {
            TokenStatus::Active => BadgeVariant::Success,
            TokenStatus::Inactive => BadgeVariant::Default,
            TokenStatus::Locked => BadgeVariant::Warning,
            TokenStatus::Revoked => BadgeVariant::Danger,
            TokenStatus::Expired => BadgeVariant::Default,
        }
    }
}

/// Token type
#[derive(Clone, PartialEq)]
pub enum TokenType {
    Smartcard,
    Yubikey,
    SoftToken,
    Hsm,
}

impl TokenType {
    fn as_str(&self) -> &'static str {
        match self {
            TokenType::Smartcard => "Smartcard",
            TokenType::Yubikey => "YubiKey",
            TokenType::SoftToken => "Software Token",
            TokenType::Hsm => "HSM",
        }
    }

    fn icon(&self) -> &'static str {
        match self {
            TokenType::Smartcard => {
                "M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z"
            }
            TokenType::Yubikey => {
                "M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"
            }
            TokenType::SoftToken => {
                "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
            }
            TokenType::Hsm => {
                "M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"
            }
        }
    }
}

/// Token data
#[derive(Clone, PartialEq)]
pub struct Token {
    pub id: String,
    pub serial_number: String,
    pub token_type: TokenType,
    pub label: String,
    pub owner: String,
    pub owner_email: String,
    pub status: TokenStatus,
    pub issued_at: String,
    pub expires_at: String,
    pub last_used: Option<String>,
    pub key_count: usize,
    pub pin_retries: Option<u8>,
}

/// SCMS page state
struct ScmsState {
    tokens: Vec<Token>,
    loading: bool,
    error: Option<String>,
    selected_token: Option<Token>,
    show_details_modal: bool,
    show_revoke_modal: bool,
    show_issue_modal: bool,
    filter_status: String,
    filter_type: String,
    search_query: String,
    current_page: usize,
}

impl Clone for ScmsState {
    fn clone(&self) -> Self {
        Self {
            tokens: self.tokens.clone(),
            loading: self.loading,
            error: self.error.clone(),
            selected_token: self.selected_token.clone(),
            show_details_modal: self.show_details_modal,
            show_revoke_modal: self.show_revoke_modal,
            show_issue_modal: self.show_issue_modal,
            filter_status: self.filter_status.clone(),
            filter_type: self.filter_type.clone(),
            search_query: self.search_query.clone(),
            current_page: self.current_page,
        }
    }
}

/// SCMS token management page
#[function_component(Scms)]
pub fn scms() -> Html {
    let state = use_state(|| ScmsState {
        tokens: get_sample_tokens(),
        loading: false,
        error: None,
        selected_token: None,
        show_details_modal: false,
        show_revoke_modal: false,
        show_issue_modal: false,
        filter_status: "all".to_string(),
        filter_type: "all".to_string(),
        search_query: String::new(),
        current_page: 1,
    });

    let on_view_details = {
        let state = state.clone();
        Callback::from(move |token: Token| {
            let mut new_state = (*state).clone();
            new_state.selected_token = Some(token);
            new_state.show_details_modal = true;
            state.set(new_state);
        })
    };

    let on_revoke_click = {
        let state = state.clone();
        Callback::from(move |token: Token| {
            let mut new_state = (*state).clone();
            new_state.selected_token = Some(token);
            new_state.show_revoke_modal = true;
            state.set(new_state);
        })
    };

    let on_issue_click = {
        let state = state.clone();
        Callback::from(move |_| {
            let mut new_state = (*state).clone();
            new_state.show_issue_modal = true;
            state.set(new_state);
        })
    };

    let on_close_modal = {
        let state = state.clone();
        Callback::from(move |_| {
            let mut new_state = (*state).clone();
            new_state.show_details_modal = false;
            new_state.show_revoke_modal = false;
            new_state.show_issue_modal = false;
            new_state.selected_token = None;
            state.set(new_state);
        })
    };

    let on_confirm_revoke = {
        let state = state.clone();
        Callback::from(move |_| {
            let mut new_state = (*state).clone();
            if let Some(ref token) = new_state.selected_token {
                // Update token status to revoked
                for t in &mut new_state.tokens {
                    if t.id == token.id {
                        t.status = TokenStatus::Revoked;
                    }
                }
            }
            new_state.show_revoke_modal = false;
            new_state.selected_token = None;
            state.set(new_state);
        })
    };

    let on_search_change = {
        let state = state.clone();
        Callback::from(move |e: InputEvent| {
            let target = e.target_unchecked_into::<web_sys::HtmlInputElement>();
            let mut new_state = (*state).clone();
            new_state.search_query = target.value();
            new_state.current_page = 1;
            state.set(new_state);
        })
    };

    let on_status_filter_change = {
        let state = state.clone();
        Callback::from(move |e: Event| {
            let target = e.target_unchecked_into::<web_sys::HtmlSelectElement>();
            let mut new_state = (*state).clone();
            new_state.filter_status = target.value();
            new_state.current_page = 1;
            state.set(new_state);
        })
    };

    let on_type_filter_change = {
        let state = state.clone();
        Callback::from(move |e: Event| {
            let target = e.target_unchecked_into::<web_sys::HtmlSelectElement>();
            let mut new_state = (*state).clone();
            new_state.filter_type = target.value();
            new_state.current_page = 1;
            state.set(new_state);
        })
    };

    let on_page_change = {
        let state = state.clone();
        Callback::from(move |page: usize| {
            let mut new_state = (*state).clone();
            new_state.current_page = page;
            state.set(new_state);
        })
    };

    // Filter tokens
    let filtered_tokens: Vec<_> = state
        .tokens
        .iter()
        .filter(|t| {
            let status_match = match state.filter_status.as_str() {
                "all" => true,
                "active" => matches!(t.status, TokenStatus::Active),
                "inactive" => matches!(t.status, TokenStatus::Inactive),
                "locked" => matches!(t.status, TokenStatus::Locked),
                "revoked" => matches!(t.status, TokenStatus::Revoked),
                _ => true,
            };
            let type_match = match state.filter_type.as_str() {
                "all" => true,
                "smartcard" => matches!(t.token_type, TokenType::Smartcard),
                "yubikey" => matches!(t.token_type, TokenType::Yubikey),
                "softtoken" => matches!(t.token_type, TokenType::SoftToken),
                "hsm" => matches!(t.token_type, TokenType::Hsm),
                _ => true,
            };
            let search_match = state.search_query.is_empty()
                || t.serial_number
                    .to_lowercase()
                    .contains(&state.search_query.to_lowercase())
                || t.label
                    .to_lowercase()
                    .contains(&state.search_query.to_lowercase())
                || t.owner
                    .to_lowercase()
                    .contains(&state.search_query.to_lowercase());
            status_match && type_match && search_match
        })
        .cloned()
        .collect();

    // Statistics
    let active_count = state
        .tokens
        .iter()
        .filter(|t| matches!(t.status, TokenStatus::Active))
        .count();
    let locked_count = state
        .tokens
        .iter()
        .filter(|t| matches!(t.status, TokenStatus::Locked))
        .count();

    let on_view = on_view_details.clone();
    let on_revoke = on_revoke_click.clone();

    let columns: Vec<Column<Token>> = vec![
        Column {
            label: "Token".to_string(),
            key: "token".to_string(),
            sortable: true,
            render: Rc::new(|token: &Token| {
                html! {
                    <div class="flex items-center gap-3">
                        <div class="flex-shrink-0 h-10 w-10 bg-gray-100 rounded-lg flex items-center justify-center">
                            <svg class="h-5 w-5 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d={token.token_type.icon()} />
                            </svg>
                        </div>
                        <div>
                            <div class="font-medium text-gray-900">{&token.label}</div>
                            <div class="text-xs text-gray-500 font-mono">{&token.serial_number}</div>
                        </div>
                    </div>
                }
            }),
        },
        Column {
            label: "Type".to_string(),
            key: "type".to_string(),
            sortable: true,
            render: Rc::new(|token: &Token| {
                html! { <span>{token.token_type.as_str()}</span> }
            }),
        },
        Column {
            label: "Owner".to_string(),
            key: "owner".to_string(),
            sortable: true,
            render: Rc::new(|token: &Token| {
                html! {
                    <div>
                        <div class="text-gray-900">{&token.owner}</div>
                        <div class="text-xs text-gray-500">{&token.owner_email}</div>
                    </div>
                }
            }),
        },
        Column {
            label: "Keys".to_string(),
            key: "keys".to_string(),
            sortable: true,
            render: Rc::new(|token: &Token| {
                html! {
                    <span class="text-gray-900">{token.key_count}</span>
                }
            }),
        },
        Column {
            label: "Last Used".to_string(),
            key: "last_used".to_string(),
            sortable: true,
            render: Rc::new(|token: &Token| {
                html! {
                    <span class="text-gray-500">
                        {token.last_used.as_deref().unwrap_or("Never")}
                    </span>
                }
            }),
        },
        Column {
            label: "Status".to_string(),
            key: "status".to_string(),
            sortable: true,
            render: Rc::new(|token: &Token| {
                html! {
                    <Badge
                        text={token.status.as_str().to_string()}
                        variant={token.status.badge_variant()}
                        dot={true}
                    />
                }
            }),
        },
        Column {
            label: "Actions".to_string(),
            key: "actions".to_string(),
            sortable: false,
            render: {
                let on_view = on_view.clone();
                let on_revoke = on_revoke.clone();
                Rc::new(move |token: &Token| {
                    let token_view = token.clone();
                    let token_revoke = token.clone();
                    let on_view = on_view.clone();
                    let on_revoke = on_revoke.clone();
                    let can_revoke =
                        matches!(token.status, TokenStatus::Active | TokenStatus::Locked);

                    html! {
                        <div class="flex gap-2">
                            <button
                                type="button"
                                class="btn btn-sm btn-secondary"
                                onclick={Callback::from(move |e: MouseEvent| {
                                    e.stop_propagation();
                                    on_view.emit(token_view.clone());
                                })}
                            >
                                {"View"}
                            </button>
                            if can_revoke {
                                <button
                                    type="button"
                                    class="btn btn-sm btn-danger"
                                    onclick={Callback::from(move |e: MouseEvent| {
                                        e.stop_propagation();
                                        on_revoke.emit(token_revoke.clone());
                                    })}
                                >
                                    {"Revoke"}
                                </button>
                            }
                        </div>
                    }
                })
            },
        },
    ];

    html! {
        <Protected permission="view_tokens">
            <div class="page-header">
                <div class="flex items-center justify-between">
                    <div>
                        <h1 class="page-title">{"Token Management"}</h1>
                        <p class="page-description">{"Manage smartcards and security tokens"}</p>
                    </div>
                    <button
                        type="button"
                        class="btn btn-primary"
                        onclick={on_issue_click}
                    >
                        <svg class="h-4 w-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
                        </svg>
                        {"Issue Token"}
                    </button>
                </div>
            </div>

            // Statistics cards
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                <div class="card">
                    <div class="card-body">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-blue-100 rounded-lg p-3">
                                <svg class="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                                </svg>
                            </div>
                            <div class="ml-4">
                                <p class="text-sm font-medium text-gray-500">{"Total Tokens"}</p>
                                <p class="text-2xl font-semibold text-gray-900">{state.tokens.len()}</p>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-green-100 rounded-lg p-3">
                                <svg class="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                            </div>
                            <div class="ml-4">
                                <p class="text-sm font-medium text-gray-500">{"Active"}</p>
                                <p class="text-2xl font-semibold text-gray-900">{active_count}</p>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-yellow-100 rounded-lg p-3">
                                <svg class="h-6 w-6 text-yellow-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                </svg>
                            </div>
                            <div class="ml-4">
                                <p class="text-sm font-medium text-gray-500">{"Locked"}</p>
                                <p class="text-2xl font-semibold text-gray-900">{locked_count}</p>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-purple-100 rounded-lg p-3">
                                <svg class="h-6 w-6 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                </svg>
                            </div>
                            <div class="ml-4">
                                <p class="text-sm font-medium text-gray-500">{"Keys Stored"}</p>
                                <p class="text-2xl font-semibold text-gray-900">
                                    {state.tokens.iter().map(|t| t.key_count).sum::<usize>()}
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            // Error alert
            if let Some(error) = &state.error {
                <div class="mb-4">
                    <Alert
                        message={error.clone()}
                        alert_type={AlertType::Error}
                        dismissible={true}
                    />
                </div>
            }

            // Filters
            <div class="card mb-4">
                <div class="card-body">
                    <div class="flex flex-wrap gap-4 items-end">
                        <div class="flex-1 min-w-[200px]">
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"Search"}
                            </label>
                            <input
                                type="text"
                                class="form-input"
                                placeholder="Search by serial, label, or owner..."
                                value={state.search_query.clone()}
                                oninput={on_search_change}
                            />
                        </div>
                        <div class="w-40">
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"Status"}
                            </label>
                            <select
                                class="form-select"
                                value={state.filter_status.clone()}
                                onchange={on_status_filter_change}
                            >
                                <option value="all">{"All Status"}</option>
                                <option value="active">{"Active"}</option>
                                <option value="inactive">{"Inactive"}</option>
                                <option value="locked">{"Locked"}</option>
                                <option value="revoked">{"Revoked"}</option>
                            </select>
                        </div>
                        <div class="w-40">
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"Type"}
                            </label>
                            <select
                                class="form-select"
                                value={state.filter_type.clone()}
                                onchange={on_type_filter_change}
                            >
                                <option value="all">{"All Types"}</option>
                                <option value="smartcard">{"Smartcard"}</option>
                                <option value="yubikey">{"YubiKey"}</option>
                                <option value="softtoken">{"Software Token"}</option>
                                <option value="hsm">{"HSM"}</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>

            // Main content
            if state.loading {
                <Loading message={Some("Loading tokens...".to_string())} />
            } else {
                <DataTable<Token>
                    data={filtered_tokens.clone()}
                    columns={columns}
                    loading={state.loading}
                    empty_message={"No tokens found".to_string()}
                    current_page={state.current_page}
                    total_items={filtered_tokens.len()}
                    page_size={10}
                    on_page_change={Some(on_page_change)}
                />
            }

            // Token Details Modal
            if state.show_details_modal {
                if let Some(token) = &state.selected_token {
                    <Modal
                        open={true}
                        title={"Token Details".to_string()}
                        on_close={on_close_modal.clone()}
                        size={ModalSize::Large}
                    >
                        <div class="space-y-6">
                            // Token info header
                            <div class="flex items-center gap-4 pb-4 border-b">
                                <div class="h-16 w-16 bg-gray-100 rounded-xl flex items-center justify-center">
                                    <svg class="h-8 w-8 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d={token.token_type.icon()} />
                                    </svg>
                                </div>
                                <div>
                                    <h3 class="text-lg font-semibold text-gray-900">{&token.label}</h3>
                                    <p class="text-sm text-gray-500 font-mono">{&token.serial_number}</p>
                                    <div class="mt-1">
                                        <Badge
                                            text={token.status.as_str().to_string()}
                                            variant={token.status.badge_variant()}
                                            dot={true}
                                        />
                                    </div>
                                </div>
                            </div>

                            // Details grid
                            <dl class="grid grid-cols-2 gap-4">
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Token Type"}</dt>
                                    <dd class="mt-1 text-sm text-gray-900">{token.token_type.as_str()}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Owner"}</dt>
                                    <dd class="mt-1 text-sm text-gray-900">{&token.owner}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Owner Email"}</dt>
                                    <dd class="mt-1 text-sm text-gray-900">{&token.owner_email}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Keys Stored"}</dt>
                                    <dd class="mt-1 text-sm text-gray-900">{token.key_count}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Issued"}</dt>
                                    <dd class="mt-1 text-sm text-gray-900">{&token.issued_at}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Expires"}</dt>
                                    <dd class="mt-1 text-sm text-gray-900">{&token.expires_at}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Last Used"}</dt>
                                    <dd class="mt-1 text-sm text-gray-900">
                                        {token.last_used.as_deref().unwrap_or("Never")}
                                    </dd>
                                </div>
                                if let Some(retries) = token.pin_retries {
                                    <div>
                                        <dt class="text-sm font-medium text-gray-500">{"PIN Retries Remaining"}</dt>
                                        <dd class="mt-1 text-sm text-gray-900">{retries}{" / 3"}</dd>
                                    </div>
                                }
                            </dl>

                            // Keys section
                            <div>
                                <h4 class="text-sm font-medium text-gray-900 mb-2">{"Stored Keys"}</h4>
                                <div class="bg-gray-50 rounded-lg p-4">
                                    <ul class="space-y-2 text-sm">
                                        <li class="flex items-center gap-2">
                                            <svg class="h-4 w-4 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                                            </svg>
                                            {"Authentication Key (RSA-2048)"}
                                        </li>
                                        <li class="flex items-center gap-2">
                                            <svg class="h-4 w-4 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                                            </svg>
                                            {"Signing Key (ECDSA P-256)"}
                                        </li>
                                        <li class="flex items-center gap-2">
                                            <svg class="h-4 w-4 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                                            </svg>
                                            {"Encryption Key (RSA-2048)"}
                                        </li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </Modal>
                }
            }

            // Revoke Modal
            if state.show_revoke_modal {
                if let Some(token) = &state.selected_token {
                    <Modal
                        open={true}
                        title={"Revoke Token".to_string()}
                        on_close={on_close_modal.clone()}
                        footer={Some(html! {
                            <>
                                <button
                                    type="button"
                                    class="btn btn-secondary"
                                    onclick={on_close_modal.reform(|_: MouseEvent| ())}
                                >
                                    {"Cancel"}
                                </button>
                                <button
                                    type="button"
                                    class="btn btn-danger"
                                    onclick={on_confirm_revoke}
                                >
                                    {"Revoke Token"}
                                </button>
                            </>
                        })}
                    >
                        <div class="space-y-4">
                            <Alert
                                alert_type={AlertType::Warning}
                                title={Some("Warning".to_string())}
                                message={"Revoking this token will immediately invalidate all keys stored on it. This action cannot be undone.".to_string()}
                            />
                            <dl class="grid grid-cols-2 gap-4">
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Token"}</dt>
                                    <dd class="text-sm text-gray-900">{&token.label}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Serial"}</dt>
                                    <dd class="text-sm text-gray-900 font-mono">{&token.serial_number}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Owner"}</dt>
                                    <dd class="text-sm text-gray-900">{&token.owner}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Keys Affected"}</dt>
                                    <dd class="text-sm text-gray-900">{token.key_count}</dd>
                                </div>
                            </dl>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">
                                    {"Revocation Reason"}
                                    <span class="text-red-500 ml-1">{"*"}</span>
                                </label>
                                <select class="form-select w-full">
                                    <option value="">{"Select a reason..."}</option>
                                    <option value="lost">{"Token Lost"}</option>
                                    <option value="stolen">{"Token Stolen"}</option>
                                    <option value="compromised">{"Suspected Compromise"}</option>
                                    <option value="terminated">{"User Terminated"}</option>
                                    <option value="superseded">{"Superseded by New Token"}</option>
                                    <option value="other">{"Other"}</option>
                                </select>
                            </div>
                        </div>
                    </Modal>
                }
            }

            // Issue Token Modal
            if state.show_issue_modal {
                <Modal
                    open={true}
                    title={"Issue New Token".to_string()}
                    on_close={on_close_modal.clone()}
                    size={ModalSize::Large}
                    footer={Some(html! {
                        <>
                            <button
                                type="button"
                                class="btn btn-secondary"
                                onclick={on_close_modal.reform(|_: MouseEvent| ())}
                            >
                                {"Cancel"}
                            </button>
                            <button
                                type="button"
                                class="btn btn-primary"
                            >
                                {"Issue Token"}
                            </button>
                        </>
                    })}
                >
                    <form class="space-y-4">
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">
                                    {"Token Type"}
                                    <span class="text-red-500 ml-1">{"*"}</span>
                                </label>
                                <select class="form-select w-full">
                                    <option value="smartcard">{"Smartcard"}</option>
                                    <option value="yubikey">{"YubiKey"}</option>
                                    <option value="softtoken">{"Software Token"}</option>
                                </select>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">
                                    {"Serial Number"}
                                    <span class="text-red-500 ml-1">{"*"}</span>
                                </label>
                                <input
                                    type="text"
                                    class="form-input w-full"
                                    placeholder="e.g., SC-2025-001234"
                                />
                            </div>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"Token Label"}
                                <span class="text-red-500 ml-1">{"*"}</span>
                            </label>
                            <input
                                type="text"
                                class="form-input w-full"
                                placeholder="e.g., Production Smartcard"
                            />
                        </div>
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">
                                    {"Owner"}
                                    <span class="text-red-500 ml-1">{"*"}</span>
                                </label>
                                <input
                                    type="text"
                                    class="form-input w-full"
                                    placeholder="Select user..."
                                />
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">
                                    {"Validity Period"}
                                </label>
                                <select class="form-select w-full">
                                    <option value="1y">{"1 Year"}</option>
                                    <option value="2y">{"2 Years"}</option>
                                    <option value="3y">{"3 Years"}</option>
                                    <option value="5y">{"5 Years"}</option>
                                </select>
                            </div>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">
                                {"Key Types to Generate"}
                            </label>
                            <div class="space-y-2">
                                <label class="flex items-center gap-2">
                                    <input type="checkbox" class="form-checkbox" checked={true} />
                                    <span class="text-sm text-gray-700">{"Authentication Key (RSA-2048)"}</span>
                                </label>
                                <label class="flex items-center gap-2">
                                    <input type="checkbox" class="form-checkbox" checked={true} />
                                    <span class="text-sm text-gray-700">{"Digital Signature Key (ECDSA P-256)"}</span>
                                </label>
                                <label class="flex items-center gap-2">
                                    <input type="checkbox" class="form-checkbox" checked={true} />
                                    <span class="text-sm text-gray-700">{"Key Encipherment Key (RSA-2048)"}</span>
                                </label>
                            </div>
                        </div>
                    </form>
                </Modal>
            }
        </Protected>
    }
}

/// Generate sample tokens for demo purposes
fn get_sample_tokens() -> Vec<Token> {
    vec![
        Token {
            id: "TOK-001".to_string(),
            serial_number: "SC-2025-001234".to_string(),
            token_type: TokenType::Smartcard,
            label: "Admin PIV Card".to_string(),
            owner: "Alice Admin".to_string(),
            owner_email: "alice.admin@example.com".to_string(),
            status: TokenStatus::Active,
            issued_at: "2025-01-01".to_string(),
            expires_at: "2027-01-01".to_string(),
            last_used: Some("2025-01-07 08:30".to_string()),
            key_count: 3,
            pin_retries: Some(3),
        },
        Token {
            id: "TOK-002".to_string(),
            serial_number: "YK-5C-12345678".to_string(),
            token_type: TokenType::Yubikey,
            label: "Developer YubiKey".to_string(),
            owner: "Bob Developer".to_string(),
            owner_email: "bob.dev@example.com".to_string(),
            status: TokenStatus::Active,
            issued_at: "2024-06-15".to_string(),
            expires_at: "2026-06-15".to_string(),
            last_used: Some("2025-01-06 17:45".to_string()),
            key_count: 2,
            pin_retries: Some(3),
        },
        Token {
            id: "TOK-003".to_string(),
            serial_number: "SC-2024-005678".to_string(),
            token_type: TokenType::Smartcard,
            label: "Operator Card".to_string(),
            owner: "Carol Operator".to_string(),
            owner_email: "carol.ops@example.com".to_string(),
            status: TokenStatus::Locked,
            issued_at: "2024-03-10".to_string(),
            expires_at: "2026-03-10".to_string(),
            last_used: Some("2025-01-05 09:12".to_string()),
            key_count: 3,
            pin_retries: Some(0),
        },
        Token {
            id: "TOK-004".to_string(),
            serial_number: "SOFT-2025-ABCD".to_string(),
            token_type: TokenType::SoftToken,
            label: "Backup Soft Token".to_string(),
            owner: "Dave Backup".to_string(),
            owner_email: "dave.backup@example.com".to_string(),
            status: TokenStatus::Inactive,
            issued_at: "2025-01-02".to_string(),
            expires_at: "2026-01-02".to_string(),
            last_used: None,
            key_count: 1,
            pin_retries: None,
        },
        Token {
            id: "TOK-005".to_string(),
            serial_number: "HSM-LUNA-001".to_string(),
            token_type: TokenType::Hsm,
            label: "Production HSM Slot 1".to_string(),
            owner: "CA Service".to_string(),
            owner_email: "ca-service@example.com".to_string(),
            status: TokenStatus::Active,
            issued_at: "2023-01-15".to_string(),
            expires_at: "2028-01-15".to_string(),
            last_used: Some("2025-01-07 09:00".to_string()),
            key_count: 5,
            pin_retries: None,
        },
        Token {
            id: "TOK-006".to_string(),
            serial_number: "SC-2023-009999".to_string(),
            token_type: TokenType::Smartcard,
            label: "Former Employee Card".to_string(),
            owner: "Eve Former".to_string(),
            owner_email: "eve.former@example.com".to_string(),
            status: TokenStatus::Revoked,
            issued_at: "2023-06-01".to_string(),
            expires_at: "2025-06-01".to_string(),
            last_used: Some("2024-12-15 14:00".to_string()),
            key_count: 3,
            pin_retries: None,
        },
    ]
}
