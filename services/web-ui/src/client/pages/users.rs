//! User Management Page
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-2 (Account Management) - User lifecycle management
//! - NIST 800-53: AC-6 (Least Privilege) - Role-based access control
//! - NIAP PP-CA: FMT_SMR.1 (Security Roles) - Role management

use std::rc::Rc;
use yew::prelude::*;

use crate::components::auth::Protected;
use crate::components::common::{
    Alert, AlertType, Badge, BadgeVariant, Column, DataTable, Loading, Modal, ModalSize,
};

/// User status
#[derive(Clone, PartialEq)]
pub enum UserStatus {
    Active,
    Inactive,
    Locked,
    Pending,
}

impl UserStatus {
    fn as_str(&self) -> &'static str {
        match self {
            UserStatus::Active => "Active",
            UserStatus::Inactive => "Inactive",
            UserStatus::Locked => "Locked",
            UserStatus::Pending => "Pending",
        }
    }

    fn badge_variant(&self) -> BadgeVariant {
        match self {
            UserStatus::Active => BadgeVariant::Success,
            UserStatus::Inactive => BadgeVariant::Default,
            UserStatus::Locked => BadgeVariant::Danger,
            UserStatus::Pending => BadgeVariant::Warning,
        }
    }
}

/// User role
#[derive(Clone, PartialEq)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub description: String,
}

/// User data
#[derive(Clone, PartialEq)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub full_name: String,
    pub status: UserStatus,
    pub roles: Vec<String>,
    pub created_at: String,
    pub last_login: Option<String>,
    pub mfa_enabled: bool,
}

/// Users page state
struct UsersState {
    users: Vec<User>,
    available_roles: Vec<Role>,
    loading: bool,
    error: Option<String>,
    selected_user: Option<User>,
    show_details_modal: bool,
    show_edit_modal: bool,
    show_create_modal: bool,
    show_disable_modal: bool,
    search_query: String,
    filter_status: String,
    filter_role: String,
    current_page: usize,
}

impl Clone for UsersState {
    fn clone(&self) -> Self {
        Self {
            users: self.users.clone(),
            available_roles: self.available_roles.clone(),
            loading: self.loading,
            error: self.error.clone(),
            selected_user: self.selected_user.clone(),
            show_details_modal: self.show_details_modal,
            show_edit_modal: self.show_edit_modal,
            show_create_modal: self.show_create_modal,
            show_disable_modal: self.show_disable_modal,
            search_query: self.search_query.clone(),
            filter_status: self.filter_status.clone(),
            filter_role: self.filter_role.clone(),
            current_page: self.current_page,
        }
    }
}

/// User management page
#[function_component(Users)]
pub fn users() -> Html {
    let state = use_state(|| UsersState {
        users: get_sample_users(),
        available_roles: get_available_roles(),
        loading: false,
        error: None,
        selected_user: None,
        show_details_modal: false,
        show_edit_modal: false,
        show_create_modal: false,
        show_disable_modal: false,
        search_query: String::new(),
        filter_status: "all".to_string(),
        filter_role: "all".to_string(),
        current_page: 1,
    });

    let on_view_details = {
        let state = state.clone();
        Callback::from(move |user: User| {
            let mut new_state = (*state).clone();
            new_state.selected_user = Some(user);
            new_state.show_details_modal = true;
            state.set(new_state);
        })
    };

    let on_edit_click = {
        let state = state.clone();
        Callback::from(move |user: User| {
            let mut new_state = (*state).clone();
            new_state.selected_user = Some(user);
            new_state.show_edit_modal = true;
            state.set(new_state);
        })
    };

    let on_disable_click = {
        let state = state.clone();
        Callback::from(move |user: User| {
            let mut new_state = (*state).clone();
            new_state.selected_user = Some(user);
            new_state.show_disable_modal = true;
            state.set(new_state);
        })
    };

    let on_create_click = {
        let state = state.clone();
        Callback::from(move |_| {
            let mut new_state = (*state).clone();
            new_state.show_create_modal = true;
            state.set(new_state);
        })
    };

    let on_close_modal = {
        let state = state.clone();
        Callback::from(move |_| {
            let mut new_state = (*state).clone();
            new_state.show_details_modal = false;
            new_state.show_edit_modal = false;
            new_state.show_create_modal = false;
            new_state.show_disable_modal = false;
            new_state.selected_user = None;
            state.set(new_state);
        })
    };

    let on_confirm_disable = {
        let state = state.clone();
        Callback::from(move |_| {
            let mut new_state = (*state).clone();
            if let Some(ref user) = new_state.selected_user {
                for u in &mut new_state.users {
                    if u.id == user.id {
                        u.status = UserStatus::Inactive;
                    }
                }
            }
            new_state.show_disable_modal = false;
            new_state.selected_user = None;
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

    let on_role_filter_change = {
        let state = state.clone();
        Callback::from(move |e: Event| {
            let target = e.target_unchecked_into::<web_sys::HtmlSelectElement>();
            let mut new_state = (*state).clone();
            new_state.filter_role = target.value();
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

    // Filter users
    let filtered_users: Vec<_> = state
        .users
        .iter()
        .filter(|u| {
            let status_match = match state.filter_status.as_str() {
                "all" => true,
                "active" => matches!(u.status, UserStatus::Active),
                "inactive" => matches!(u.status, UserStatus::Inactive),
                "locked" => matches!(u.status, UserStatus::Locked),
                "pending" => matches!(u.status, UserStatus::Pending),
                _ => true,
            };
            let role_match = state.filter_role == "all"
                || u.roles
                    .iter()
                    .any(|r| r.to_lowercase() == state.filter_role.to_lowercase());
            let search_match = state.search_query.is_empty()
                || u.username
                    .to_lowercase()
                    .contains(&state.search_query.to_lowercase())
                || u.email
                    .to_lowercase()
                    .contains(&state.search_query.to_lowercase())
                || u.full_name
                    .to_lowercase()
                    .contains(&state.search_query.to_lowercase());
            status_match && role_match && search_match
        })
        .cloned()
        .collect();

    // Statistics
    let active_count = state
        .users
        .iter()
        .filter(|u| matches!(u.status, UserStatus::Active))
        .count();
    let admin_count = state
        .users
        .iter()
        .filter(|u| u.roles.iter().any(|r| r == "admin"))
        .count();

    let on_view = on_view_details.clone();
    let on_edit = on_edit_click.clone();
    let on_disable = on_disable_click.clone();

    let columns: Vec<Column<User>> = vec![
        Column {
            label: "User".to_string(),
            key: "user".to_string(),
            sortable: true,
            render: Rc::new(|user: &User| {
                let initials: String = user
                    .full_name
                    .split_whitespace()
                    .take(2)
                    .filter_map(|s| s.chars().next())
                    .collect();
                html! {
                    <div class="flex items-center gap-3">
                        <div class="flex-shrink-0 h-10 w-10 bg-primary-100 rounded-full flex items-center justify-center">
                            <span class="text-sm font-medium text-primary-700">
                                {initials.to_uppercase()}
                            </span>
                        </div>
                        <div>
                            <div class="font-medium text-gray-900">{&user.full_name}</div>
                            <div class="text-xs text-gray-500">{&user.username}</div>
                        </div>
                    </div>
                }
            }),
        },
        Column {
            label: "Email".to_string(),
            key: "email".to_string(),
            sortable: true,
            render: Rc::new(|user: &User| {
                html! { <span class="text-gray-500">{&user.email}</span> }
            }),
        },
        Column {
            label: "Roles".to_string(),
            key: "roles".to_string(),
            sortable: false,
            render: Rc::new(|user: &User| {
                html! {
                    <div class="flex flex-wrap gap-1">
                        { for user.roles.iter().take(3).map(|role| {
                            let variant = match role.as_str() {
                                "admin" => BadgeVariant::Danger,
                                "ca_operator" => BadgeVariant::Primary,
                                "auditor" => BadgeVariant::Info,
                                _ => BadgeVariant::Default,
                            };
                            html! {
                                <Badge text={role.clone()} variant={variant} size={super::super::components::common::BadgeSize::Small} />
                            }
                        })}
                        if user.roles.len() > 3 {
                            <span class="text-xs text-gray-400">{format!("+{}", user.roles.len() - 3)}</span>
                        }
                    </div>
                }
            }),
        },
        Column {
            label: "MFA".to_string(),
            key: "mfa".to_string(),
            sortable: true,
            render: Rc::new(|user: &User| {
                if user.mfa_enabled {
                    html! {
                        <svg class="h-5 w-5 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                    }
                } else {
                    html! {
                        <svg class="h-5 w-5 text-gray-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                        </svg>
                    }
                }
            }),
        },
        Column {
            label: "Last Login".to_string(),
            key: "last_login".to_string(),
            sortable: true,
            render: Rc::new(|user: &User| {
                html! {
                    <span class="text-gray-500">
                        {user.last_login.as_deref().unwrap_or("Never")}
                    </span>
                }
            }),
        },
        Column {
            label: "Status".to_string(),
            key: "status".to_string(),
            sortable: true,
            render: Rc::new(|user: &User| {
                html! {
                    <Badge
                        text={user.status.as_str().to_string()}
                        variant={user.status.badge_variant()}
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
                let on_edit = on_edit.clone();
                let on_disable = on_disable.clone();
                Rc::new(move |user: &User| {
                    let user_view = user.clone();
                    let user_edit = user.clone();
                    let user_disable = user.clone();
                    let on_view = on_view.clone();
                    let on_edit = on_edit.clone();
                    let on_disable = on_disable.clone();
                    let can_disable = matches!(user.status, UserStatus::Active);

                    html! {
                        <div class="flex gap-1">
                            <button
                                type="button"
                                class="p-1 text-gray-400 hover:text-gray-600"
                                title="View details"
                                onclick={Callback::from(move |e: MouseEvent| {
                                    e.stop_propagation();
                                    on_view.emit(user_view.clone());
                                })}
                            >
                                <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                                </svg>
                            </button>
                            <button
                                type="button"
                                class="p-1 text-gray-400 hover:text-blue-600"
                                title="Edit user"
                                onclick={Callback::from(move |e: MouseEvent| {
                                    e.stop_propagation();
                                    on_edit.emit(user_edit.clone());
                                })}
                            >
                                <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                                </svg>
                            </button>
                            if can_disable {
                                <button
                                    type="button"
                                    class="p-1 text-gray-400 hover:text-red-600"
                                    title="Disable user"
                                    onclick={Callback::from(move |e: MouseEvent| {
                                        e.stop_propagation();
                                        on_disable.emit(user_disable.clone());
                                    })}
                                >
                                    <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                                    </svg>
                                </button>
                            }
                        </div>
                    }
                })
            },
        },
    ];

    html! {
        <Protected permission="manage_users">
            <div class="page-header">
                <div class="flex items-center justify-between">
                    <div>
                        <h1 class="page-title">{"User Management"}</h1>
                        <p class="page-description">{"Manage users and role assignments"}</p>
                    </div>
                    <button
                        type="button"
                        class="btn btn-primary"
                        onclick={on_create_click}
                    >
                        <svg class="h-4 w-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
                        </svg>
                        {"Add User"}
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
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
                                </svg>
                            </div>
                            <div class="ml-4">
                                <p class="text-sm font-medium text-gray-500">{"Total Users"}</p>
                                <p class="text-2xl font-semibold text-gray-900">{state.users.len()}</p>
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
                                <p class="text-sm font-medium text-gray-500">{"Active Users"}</p>
                                <p class="text-2xl font-semibold text-gray-900">{active_count}</p>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-red-100 rounded-lg p-3">
                                <svg class="h-6 w-6 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                </svg>
                            </div>
                            <div class="ml-4">
                                <p class="text-sm font-medium text-gray-500">{"Administrators"}</p>
                                <p class="text-2xl font-semibold text-gray-900">{admin_count}</p>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-body">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 bg-purple-100 rounded-lg p-3">
                                <svg class="h-6 w-6 text-purple-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                                </svg>
                            </div>
                            <div class="ml-4">
                                <p class="text-sm font-medium text-gray-500">{"Roles"}</p>
                                <p class="text-2xl font-semibold text-gray-900">{state.available_roles.len()}</p>
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
                                placeholder="Search by name, username, or email..."
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
                                <option value="pending">{"Pending"}</option>
                            </select>
                        </div>
                        <div class="w-40">
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"Role"}
                            </label>
                            <select
                                class="form-select"
                                value={state.filter_role.clone()}
                                onchange={on_role_filter_change}
                            >
                                <option value="all">{"All Roles"}</option>
                                { for state.available_roles.iter().map(|r| {
                                    html! {
                                        <option value={r.id.clone()}>{&r.name}</option>
                                    }
                                })}
                            </select>
                        </div>
                    </div>
                </div>
            </div>

            // Main content
            if state.loading {
                <Loading message={Some("Loading users...".to_string())} />
            } else {
                <DataTable<User>
                    data={filtered_users.clone()}
                    columns={columns}
                    loading={state.loading}
                    empty_message={"No users found".to_string()}
                    current_page={state.current_page}
                    total_items={filtered_users.len()}
                    page_size={10}
                    on_page_change={Some(on_page_change)}
                />
            }

            // User Details Modal
            if state.show_details_modal {
                if let Some(user) = &state.selected_user {
                    <Modal
                        open={true}
                        title={"User Details".to_string()}
                        on_close={on_close_modal.clone()}
                        size={ModalSize::Large}
                    >
                        <div class="space-y-6">
                            // User header
                            <div class="flex items-center gap-4 pb-4 border-b">
                                <div class="h-16 w-16 bg-primary-100 rounded-full flex items-center justify-center">
                                    <span class="text-xl font-semibold text-primary-700">
                                        {user.full_name.split_whitespace().take(2).filter_map(|s| s.chars().next()).collect::<String>().to_uppercase()}
                                    </span>
                                </div>
                                <div>
                                    <h3 class="text-lg font-semibold text-gray-900">{&user.full_name}</h3>
                                    <p class="text-sm text-gray-500">{&user.email}</p>
                                    <div class="mt-1">
                                        <Badge
                                            text={user.status.as_str().to_string()}
                                            variant={user.status.badge_variant()}
                                            dot={true}
                                        />
                                    </div>
                                </div>
                            </div>

                            // Details grid
                            <dl class="grid grid-cols-2 gap-4">
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Username"}</dt>
                                    <dd class="mt-1 text-sm text-gray-900">{&user.username}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Email"}</dt>
                                    <dd class="mt-1 text-sm text-gray-900">{&user.email}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Created"}</dt>
                                    <dd class="mt-1 text-sm text-gray-900">{&user.created_at}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Last Login"}</dt>
                                    <dd class="mt-1 text-sm text-gray-900">
                                        {user.last_login.as_deref().unwrap_or("Never")}
                                    </dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"MFA Status"}</dt>
                                    <dd class="mt-1 text-sm text-gray-900">
                                        if user.mfa_enabled {
                                            <span class="text-green-600">{"Enabled"}</span>
                                        } else {
                                            <span class="text-yellow-600">{"Not Configured"}</span>
                                        }
                                    </dd>
                                </div>
                            </dl>

                            // Roles section
                            <div>
                                <h4 class="text-sm font-medium text-gray-900 mb-2">{"Assigned Roles"}</h4>
                                <div class="flex flex-wrap gap-2">
                                    { for user.roles.iter().map(|role| {
                                        let variant = match role.as_str() {
                                            "admin" => BadgeVariant::Danger,
                                            "ca_operator" => BadgeVariant::Primary,
                                            "auditor" => BadgeVariant::Info,
                                            _ => BadgeVariant::Default,
                                        };
                                        html! {
                                            <Badge text={role.clone()} variant={variant} />
                                        }
                                    })}
                                </div>
                            </div>
                        </div>
                    </Modal>
                }
            }

            // Edit User Modal
            if state.show_edit_modal {
                if let Some(user) = &state.selected_user {
                    <Modal
                        open={true}
                        title={"Edit User".to_string()}
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
                                    {"Save Changes"}
                                </button>
                            </>
                        })}
                    >
                        <form class="space-y-4">
                            <div class="grid grid-cols-2 gap-4">
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-1">
                                        {"Full Name"}
                                        <span class="text-red-500 ml-1">{"*"}</span>
                                    </label>
                                    <input
                                        type="text"
                                        class="form-input w-full"
                                        value={user.full_name.clone()}
                                    />
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-1">
                                        {"Username"}
                                    </label>
                                    <input
                                        type="text"
                                        class="form-input w-full bg-gray-50"
                                        value={user.username.clone()}
                                        disabled={true}
                                    />
                                </div>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">
                                    {"Email"}
                                    <span class="text-red-500 ml-1">{"*"}</span>
                                </label>
                                <input
                                    type="email"
                                    class="form-input w-full"
                                    value={user.email.clone()}
                                />
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">
                                    {"Status"}
                                </label>
                                <select class="form-select w-full">
                                    <option value="active" selected={matches!(user.status, UserStatus::Active)}>{"Active"}</option>
                                    <option value="inactive" selected={matches!(user.status, UserStatus::Inactive)}>{"Inactive"}</option>
                                    <option value="locked" selected={matches!(user.status, UserStatus::Locked)}>{"Locked"}</option>
                                </select>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">
                                    {"Roles"}
                                </label>
                                <div class="space-y-2 max-h-48 overflow-y-auto border rounded-lg p-3">
                                    { for state.available_roles.iter().map(|role| {
                                        let is_checked = user.roles.contains(&role.id);
                                        html! {
                                            <label class="flex items-start gap-2">
                                                <input
                                                    type="checkbox"
                                                    class="form-checkbox mt-0.5"
                                                    checked={is_checked}
                                                />
                                                <div>
                                                    <span class="text-sm font-medium text-gray-700">{&role.name}</span>
                                                    <p class="text-xs text-gray-500">{&role.description}</p>
                                                </div>
                                            </label>
                                        }
                                    })}
                                </div>
                            </div>
                        </form>
                    </Modal>
                }
            }

            // Create User Modal
            if state.show_create_modal {
                <Modal
                    open={true}
                    title={"Add New User".to_string()}
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
                                {"Create User"}
                            </button>
                        </>
                    })}
                >
                    <form class="space-y-4">
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">
                                    {"Full Name"}
                                    <span class="text-red-500 ml-1">{"*"}</span>
                                </label>
                                <input
                                    type="text"
                                    class="form-input w-full"
                                    placeholder="John Doe"
                                />
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">
                                    {"Username"}
                                    <span class="text-red-500 ml-1">{"*"}</span>
                                </label>
                                <input
                                    type="text"
                                    class="form-input w-full"
                                    placeholder="johndoe"
                                />
                            </div>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                {"Email"}
                                <span class="text-red-500 ml-1">{"*"}</span>
                            </label>
                            <input
                                type="email"
                                class="form-input w-full"
                                placeholder="john.doe@example.com"
                            />
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">
                                {"Roles"}
                            </label>
                            <div class="space-y-2 max-h-48 overflow-y-auto border rounded-lg p-3">
                                { for state.available_roles.iter().map(|role| {
                                    html! {
                                        <label class="flex items-start gap-2">
                                            <input type="checkbox" class="form-checkbox mt-0.5" />
                                            <div>
                                                <span class="text-sm font-medium text-gray-700">{&role.name}</span>
                                                <p class="text-xs text-gray-500">{&role.description}</p>
                                            </div>
                                        </label>
                                    }
                                })}
                            </div>
                        </div>
                        <Alert
                            alert_type={AlertType::Info}
                            message={"An email will be sent to the user with instructions to set their password and configure MFA.".to_string()}
                        />
                    </form>
                </Modal>
            }

            // Disable User Modal
            if state.show_disable_modal {
                if let Some(user) = &state.selected_user {
                    <Modal
                        open={true}
                        title={"Disable User".to_string()}
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
                                    onclick={on_confirm_disable}
                                >
                                    {"Disable User"}
                                </button>
                            </>
                        })}
                    >
                        <div class="space-y-4">
                            <Alert
                                alert_type={AlertType::Warning}
                                message={"Disabling this user will immediately revoke their access to the system. Their tokens and certificates will remain valid until explicitly revoked.".to_string()}
                            />
                            <dl class="grid grid-cols-2 gap-4">
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"User"}</dt>
                                    <dd class="text-sm text-gray-900">{&user.full_name}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Username"}</dt>
                                    <dd class="text-sm text-gray-900">{&user.username}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Email"}</dt>
                                    <dd class="text-sm text-gray-900">{&user.email}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Roles"}</dt>
                                    <dd class="text-sm text-gray-900">{user.roles.join(", ")}</dd>
                                </div>
                            </dl>
                        </div>
                    </Modal>
                }
            }
        </Protected>
    }
}

/// Get available roles
fn get_available_roles() -> Vec<Role> {
    vec![
        Role {
            id: "admin".to_string(),
            name: "Administrator".to_string(),
            description: "Full system access".to_string(),
        },
        Role {
            id: "ca_operator".to_string(),
            name: "CA Operator".to_string(),
            description: "Issue and revoke certificates".to_string(),
        },
        Role {
            id: "ra_operator".to_string(),
            name: "RA Operator".to_string(),
            description: "Registration authority functions".to_string(),
        },
        Role {
            id: "auditor".to_string(),
            name: "Auditor".to_string(),
            description: "View audit logs and reports".to_string(),
        },
        Role {
            id: "approver".to_string(),
            name: "Approver".to_string(),
            description: "Approve certificate requests".to_string(),
        },
        Role {
            id: "user_manager".to_string(),
            name: "User Manager".to_string(),
            description: "Manage user accounts".to_string(),
        },
        Role {
            id: "viewer".to_string(),
            name: "Viewer".to_string(),
            description: "Read-only access".to_string(),
        },
    ]
}

/// Generate sample users for demo purposes
fn get_sample_users() -> Vec<User> {
    vec![
        User {
            id: "USR-001".to_string(),
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            full_name: "Alice Administrator".to_string(),
            status: UserStatus::Active,
            roles: vec!["admin".to_string()],
            created_at: "2024-01-15".to_string(),
            last_login: Some("2025-01-07 09:15".to_string()),
            mfa_enabled: true,
        },
        User {
            id: "USR-002".to_string(),
            username: "caoperator".to_string(),
            email: "ca.operator@example.com".to_string(),
            full_name: "Bob CA Operator".to_string(),
            status: UserStatus::Active,
            roles: vec!["ca_operator".to_string(), "approver".to_string()],
            created_at: "2024-02-20".to_string(),
            last_login: Some("2025-01-07 08:30".to_string()),
            mfa_enabled: true,
        },
        User {
            id: "USR-003".to_string(),
            username: "auditor".to_string(),
            email: "auditor@example.com".to_string(),
            full_name: "Carol Auditor".to_string(),
            status: UserStatus::Active,
            roles: vec!["auditor".to_string()],
            created_at: "2024-03-10".to_string(),
            last_login: Some("2025-01-06 14:22".to_string()),
            mfa_enabled: true,
        },
        User {
            id: "USR-004".to_string(),
            username: "raoperator".to_string(),
            email: "ra.operator@example.com".to_string(),
            full_name: "Dave RA Operator".to_string(),
            status: UserStatus::Active,
            roles: vec!["ra_operator".to_string()],
            created_at: "2024-04-05".to_string(),
            last_login: Some("2025-01-05 16:45".to_string()),
            mfa_enabled: false,
        },
        User {
            id: "USR-005".to_string(),
            username: "viewer".to_string(),
            email: "viewer@example.com".to_string(),
            full_name: "Eve Viewer".to_string(),
            status: UserStatus::Active,
            roles: vec!["viewer".to_string()],
            created_at: "2024-05-12".to_string(),
            last_login: Some("2025-01-04 10:00".to_string()),
            mfa_enabled: false,
        },
        User {
            id: "USR-006".to_string(),
            username: "locked_user".to_string(),
            email: "locked@example.com".to_string(),
            full_name: "Frank Locked".to_string(),
            status: UserStatus::Locked,
            roles: vec!["viewer".to_string()],
            created_at: "2024-06-01".to_string(),
            last_login: Some("2024-12-15 09:00".to_string()),
            mfa_enabled: true,
        },
        User {
            id: "USR-007".to_string(),
            username: "newuser".to_string(),
            email: "new.user@example.com".to_string(),
            full_name: "Grace New".to_string(),
            status: UserStatus::Pending,
            roles: vec!["viewer".to_string()],
            created_at: "2025-01-06".to_string(),
            last_login: None,
            mfa_enabled: false,
        },
    ]
}
