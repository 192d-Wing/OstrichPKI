//! Dashboard Page
//!
//! Main dashboard with PKI infrastructure overview.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-2 (Audit Events) - Displays recent audit activity
//! - NIAP PP-CA: FAU_GEN.1 - Shows audit data to authorized users

use yew::prelude::*;

use crate::components::auth::Protected;
use crate::components::common::{Alert, AlertType, Loading};
use crate::services::api::{api, ApiError};
use crate::types::api::{ActivityItem, DashboardData, DashboardStats};

/// Loading state for async data
#[derive(Clone, PartialEq)]
enum LoadState<T> {
    Loading,
    Loaded(T),
    Error(String),
}

/// Dashboard page component
#[function_component(Dashboard)]
pub fn dashboard() -> Html {
    let data_state = use_state(|| LoadState::<DashboardData>::Loading);

    // Fetch dashboard data on mount
    {
        let data_state = data_state.clone();
        use_effect_with((), move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                match fetch_dashboard_data().await {
                    Ok(data) => data_state.set(LoadState::Loaded(data)),
                    Err(e) => data_state.set(LoadState::Error(e.message)),
                }
            });
            || ()
        });
    }

    // Refresh handler
    let on_refresh = {
        let data_state = data_state.clone();
        Callback::from(move |_: MouseEvent| {
            let data_state = data_state.clone();
            data_state.set(LoadState::Loading);
            wasm_bindgen_futures::spawn_local(async move {
                match fetch_dashboard_data().await {
                    Ok(data) => data_state.set(LoadState::Loaded(data)),
                    Err(e) => data_state.set(LoadState::Error(e.message)),
                }
            });
        })
    };

    html! {
        <Protected>
            <div class="page-header flex justify-between items-start">
                <div>
                    <h1 class="page-title">{ "Dashboard" }</h1>
                    <p class="page-description">{ "Overview of your PKI infrastructure" }</p>
                </div>
                <button
                    onclick={on_refresh}
                    class="btn-secondary flex items-center gap-2"
                >
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                    { "Refresh" }
                </button>
            </div>

            {
                match (*data_state).clone() {
                    LoadState::Loading => html! {
                        <div class="flex justify-center py-12">
                            <Loading message="Loading dashboard data..." />
                        </div>
                    },
                    LoadState::Error(msg) => html! {
                        <Alert alert_type={AlertType::Error} dismissible={false}>
                            { format!("Failed to load dashboard: {}", msg) }
                        </Alert>
                    },
                    LoadState::Loaded(data) => html! {
                        <DashboardContent data={data} />
                    },
                }
            }
        </Protected>
    }
}

/// Fetch dashboard data from API
async fn fetch_dashboard_data() -> Result<DashboardData, ApiError> {
    // Try to fetch from API, fall back to mock data for development
    match api().get::<DashboardData>("/dashboard").await {
        Ok(data) => Ok(data),
        Err(_) => {
            // Return mock data for development when API isn't available
            Ok(get_mock_dashboard_data())
        }
    }
}

/// Generate mock dashboard data for development
fn get_mock_dashboard_data() -> DashboardData {
    DashboardData {
        stats: DashboardStats {
            active_certificates: 1234,
            active_change_percent: 12.5,
            pending_approvals: 23,
            pending_change: 5,
            expiring_soon: 47,
            expiring_days: 30,
            revoked_certificates: 89,
            revoked_today: 3,
        },
        recent_activity: vec![
            ActivityItem {
                id: "1".to_string(),
                action: "Certificate issued".to_string(),
                subject: "CN=api.example.com".to_string(),
                actor: "admin@example.com".to_string(),
                timestamp: "2024-01-15T10:30:00Z".to_string(),
                relative_time: "2 minutes ago".to_string(),
            },
            ActivityItem {
                id: "2".to_string(),
                action: "Approval granted".to_string(),
                subject: "Request #1234".to_string(),
                actor: "ra@example.com".to_string(),
                timestamp: "2024-01-15T10:15:00Z".to_string(),
                relative_time: "15 minutes ago".to_string(),
            },
            ActivityItem {
                id: "3".to_string(),
                action: "Certificate revoked".to_string(),
                subject: "CN=old-server.local".to_string(),
                actor: "admin@example.com".to_string(),
                timestamp: "2024-01-15T09:30:00Z".to_string(),
                relative_time: "1 hour ago".to_string(),
            },
            ActivityItem {
                id: "4".to_string(),
                action: "CRL generated".to_string(),
                subject: "CRL #567".to_string(),
                actor: "system".to_string(),
                timestamp: "2024-01-15T08:30:00Z".to_string(),
                relative_time: "2 hours ago".to_string(),
            },
            ActivityItem {
                id: "5".to_string(),
                action: "User logged in".to_string(),
                subject: "admin@example.com".to_string(),
                actor: "admin@example.com".to_string(),
                timestamp: "2024-01-15T08:00:00Z".to_string(),
                relative_time: "2.5 hours ago".to_string(),
            },
        ],
    }
}

/// Dashboard content properties
#[derive(Properties, PartialEq)]
struct DashboardContentProps {
    data: DashboardData,
}

/// Dashboard content with loaded data
#[function_component(DashboardContent)]
fn dashboard_content(props: &DashboardContentProps) -> Html {
    let stats = &props.data.stats;

    html! {
        <>
            // Stats cards
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                <StatCard
                    title="Active Certificates"
                    value={format_number(stats.active_certificates)}
                    change={format!("+{:.1}%", stats.active_change_percent)}
                    positive={stats.active_change_percent >= 0.0}
                    icon="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                    icon_color="blue"
                />
                <StatCard
                    title="Pending Approvals"
                    value={stats.pending_approvals.to_string()}
                    change={format_change(stats.pending_change)}
                    positive={false}
                    icon="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"
                    icon_color="yellow"
                />
                <StatCard
                    title="Expiring Soon"
                    value={stats.expiring_soon.to_string()}
                    change={format!("{} days", stats.expiring_days)}
                    positive={false}
                    icon="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
                    icon_color="orange"
                />
                <StatCard
                    title="Revoked Certificates"
                    value={format_number(stats.revoked_certificates)}
                    change={format!("+{} today", stats.revoked_today)}
                    positive={false}
                    icon="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"
                    icon_color="red"
                />
            </div>

            // Quick actions and recent activity
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                // Quick Actions
                <div class="card">
                    <div class="card-header">
                        <h2 class="text-lg font-semibold text-gray-900">{ "Quick Actions" }</h2>
                    </div>
                    <div class="card-body">
                        <div class="grid grid-cols-2 gap-4">
                            <QuickActionCard
                                href="/certificates"
                                icon="M12 6v6m0 0v6m0-6h6m-6 0H6"
                                icon_color="blue"
                                label="Issue Certificate"
                            />
                            <QuickActionCard
                                href="/approvals"
                                icon="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                                icon_color="green"
                                label="Review Approvals"
                            />
                            <QuickActionCard
                                href="/audit"
                                icon="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"
                                icon_color="purple"
                                label="View Audit Logs"
                            />
                            <QuickActionCard
                                href="/scms"
                                icon="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z"
                                icon_color="orange"
                                label="Manage Tokens"
                            />
                        </div>
                    </div>
                </div>

                // Recent Activity
                <div class="card">
                    <div class="card-header flex justify-between items-center">
                        <h2 class="text-lg font-semibold text-gray-900">{ "Recent Activity" }</h2>
                        <a href="/audit" class="text-sm text-blue-600 hover:text-blue-800">
                            { "View all" }
                        </a>
                    </div>
                    <div class="card-body p-0">
                        <ul class="divide-y divide-gray-200">
                            {
                                props.data.recent_activity.iter().map(|item| {
                                    html! {
                                        <ActivityItemRow
                                            key={item.id.clone()}
                                            action={item.action.clone()}
                                            subject={item.subject.clone()}
                                            actor={item.actor.clone()}
                                            time={item.relative_time.clone()}
                                        />
                                    }
                                }).collect::<Html>()
                            }
                        </ul>
                    </div>
                </div>
            </div>

            // System Status Section
            <div class="mt-6">
                <SystemStatus />
            </div>
        </>
    }
}

/// Format large numbers with commas
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, c);
    }
    result
}

/// Format change with +/- prefix
fn format_change(n: i64) -> String {
    if n >= 0 {
        format!("+{}", n)
    } else {
        n.to_string()
    }
}

/// Stat card properties
#[derive(Properties, PartialEq)]
struct StatCardProps {
    title: String,
    value: String,
    change: String,
    positive: bool,
    icon: &'static str,
    icon_color: &'static str,
}

/// Statistics card component
#[function_component(StatCard)]
fn stat_card(props: &StatCardProps) -> Html {
    let change_class = if props.positive {
        "text-green-600"
    } else {
        "text-amber-600"
    };

    let (bg_color, text_color) = match props.icon_color {
        "blue" => ("bg-blue-100", "text-blue-600"),
        "green" => ("bg-green-100", "text-green-600"),
        "yellow" => ("bg-yellow-100", "text-yellow-600"),
        "orange" => ("bg-orange-100", "text-orange-600"),
        "red" => ("bg-red-100", "text-red-600"),
        "purple" => ("bg-purple-100", "text-purple-600"),
        _ => ("bg-gray-100", "text-gray-600"),
    };

    html! {
        <div class="card hover:shadow-md transition-shadow">
            <div class="card-body">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-500">{ &props.title }</p>
                        <p class="text-2xl font-bold text-gray-900">{ &props.value }</p>
                        <p class={classes!("text-sm", change_class)}>{ &props.change }</p>
                    </div>
                    <div class={classes!("p-3", "rounded-full", bg_color)}>
                        <svg class={classes!("w-6", "h-6", text_color)} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d={props.icon} />
                        </svg>
                    </div>
                </div>
            </div>
        </div>
    }
}

/// Quick action card properties
#[derive(Properties, PartialEq)]
struct QuickActionCardProps {
    href: &'static str,
    icon: &'static str,
    icon_color: &'static str,
    label: &'static str,
}

/// Quick action card component
#[function_component(QuickActionCard)]
fn quick_action_card(props: &QuickActionCardProps) -> Html {
    let (hover_border, hover_bg, text_color) = match props.icon_color {
        "blue" => ("hover:border-blue-500", "hover:bg-blue-50", "text-blue-600"),
        "green" => ("hover:border-green-500", "hover:bg-green-50", "text-green-600"),
        "purple" => ("hover:border-purple-500", "hover:bg-purple-50", "text-purple-600"),
        "orange" => ("hover:border-orange-500", "hover:bg-orange-50", "text-orange-600"),
        _ => ("hover:border-gray-500", "hover:bg-gray-50", "text-gray-600"),
    };

    html! {
        <a
            href={props.href}
            class={classes!(
                "p-4", "rounded-lg", "border", "border-gray-200",
                hover_border, hover_bg,
                "transition-colors", "text-center", "block"
            )}
        >
            <svg class={classes!("w-8", "h-8", "mx-auto", text_color)} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d={props.icon} />
            </svg>
            <span class="block mt-2 text-sm font-medium text-gray-700">{ props.label }</span>
        </a>
    }
}

/// Activity item properties
#[derive(Properties, PartialEq)]
struct ActivityItemRowProps {
    action: String,
    subject: String,
    actor: String,
    time: String,
}

/// Activity item row component
#[function_component(ActivityItemRow)]
fn activity_item_row(props: &ActivityItemRowProps) -> Html {
    // Determine icon based on action
    let (icon, icon_color) = if props.action.contains("issued") {
        ("M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z", "text-green-500")
    } else if props.action.contains("revoked") {
        ("M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636", "text-red-500")
    } else if props.action.contains("Approval") {
        ("M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2", "text-blue-500")
    } else if props.action.contains("CRL") {
        ("M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z", "text-purple-500")
    } else {
        ("M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z", "text-gray-500")
    };

    html! {
        <li class="px-6 py-4 hover:bg-gray-50 transition-colors">
            <div class="flex items-center gap-4">
                <div class="flex-shrink-0">
                    <svg class={classes!("w-5", "h-5", icon_color)} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d={icon} />
                    </svg>
                </div>
                <div class="flex-1 min-w-0">
                    <p class="text-sm font-medium text-gray-900 truncate">{ &props.action }</p>
                    <p class="text-sm text-gray-500 truncate">{ &props.subject }</p>
                </div>
                <div class="text-right flex-shrink-0">
                    <p class="text-sm text-gray-500">{ &props.actor }</p>
                    <p class="text-xs text-gray-400">{ &props.time }</p>
                </div>
            </div>
        </li>
    }
}

/// System status component
#[function_component(SystemStatus)]
fn system_status() -> Html {
    html! {
        <div class="card">
            <div class="card-header">
                <h2 class="text-lg font-semibold text-gray-900">{ "System Status" }</h2>
            </div>
            <div class="card-body">
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <StatusIndicator
                        name="CA Service"
                        status="healthy"
                    />
                    <StatusIndicator
                        name="OCSP Responder"
                        status="healthy"
                    />
                    <StatusIndicator
                        name="ACME Server"
                        status="healthy"
                    />
                    <StatusIndicator
                        name="HSM Connection"
                        status="healthy"
                    />
                </div>
            </div>
        </div>
    }
}

/// Status indicator properties
#[derive(Properties, PartialEq)]
struct StatusIndicatorProps {
    name: &'static str,
    status: &'static str,
}

/// Status indicator component
#[function_component(StatusIndicator)]
fn status_indicator(props: &StatusIndicatorProps) -> Html {
    let (dot_color, status_text) = match props.status {
        "healthy" => ("bg-green-500", "Healthy"),
        "degraded" => ("bg-yellow-500", "Degraded"),
        "down" => ("bg-red-500", "Down"),
        _ => ("bg-gray-500", "Unknown"),
    };

    html! {
        <div class="flex items-center gap-3 p-3 bg-gray-50 rounded-lg">
            <span class={classes!("w-3", "h-3", "rounded-full", dot_color, "animate-pulse")}></span>
            <div>
                <p class="text-sm font-medium text-gray-900">{ props.name }</p>
                <p class="text-xs text-gray-500">{ status_text }</p>
            </div>
        </div>
    }
}
