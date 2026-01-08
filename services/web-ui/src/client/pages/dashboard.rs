//! Dashboard Page

use yew::prelude::*;

use crate::components::auth::Protected;

/// Dashboard page component
#[function_component(Dashboard)]
pub fn dashboard() -> Html {
    html! {
        <Protected>
            <div class="page-header">
                <h1 class="page-title">{ "Dashboard" }</h1>
                <p class="page-description">{ "Overview of your PKI infrastructure" }</p>
            </div>

            // Stats cards
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                <StatCard
                    title="Active Certificates"
                    value="1,234"
                    change="+12%"
                    positive={true}
                    icon="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
                <StatCard
                    title="Pending Approvals"
                    value="23"
                    change="+5"
                    positive={false}
                    icon="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"
                />
                <StatCard
                    title="Certificates Expiring"
                    value="47"
                    change="30 days"
                    positive={false}
                    icon="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
                />
                <StatCard
                    title="Revoked Certificates"
                    value="89"
                    change="+3 today"
                    positive={false}
                    icon="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"
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
                            <a href="/certificates" class="p-4 rounded-lg border border-gray-200 hover:border-blue-500 hover:bg-blue-50 transition-colors text-center">
                                <svg class="w-8 h-8 mx-auto text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                                </svg>
                                <span class="block mt-2 text-sm font-medium text-gray-700">{ "Issue Certificate" }</span>
                            </a>
                            <a href="/approvals" class="p-4 rounded-lg border border-gray-200 hover:border-green-500 hover:bg-green-50 transition-colors text-center">
                                <svg class="w-8 h-8 mx-auto text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                                <span class="block mt-2 text-sm font-medium text-gray-700">{ "Review Approvals" }</span>
                            </a>
                            <a href="/audit" class="p-4 rounded-lg border border-gray-200 hover:border-purple-500 hover:bg-purple-50 transition-colors text-center">
                                <svg class="w-8 h-8 mx-auto text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
                                </svg>
                                <span class="block mt-2 text-sm font-medium text-gray-700">{ "View Audit Logs" }</span>
                            </a>
                            <a href="/scms" class="p-4 rounded-lg border border-gray-200 hover:border-orange-500 hover:bg-orange-50 transition-colors text-center">
                                <svg class="w-8 h-8 mx-auto text-orange-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
                                </svg>
                                <span class="block mt-2 text-sm font-medium text-gray-700">{ "Manage Tokens" }</span>
                            </a>
                        </div>
                    </div>
                </div>

                // Recent Activity
                <div class="card">
                    <div class="card-header">
                        <h2 class="text-lg font-semibold text-gray-900">{ "Recent Activity" }</h2>
                    </div>
                    <div class="card-body p-0">
                        <ul class="divide-y divide-gray-200">
                            <ActivityItem
                                action="Certificate issued"
                                subject="CN=api.example.com"
                                actor="admin@example.com"
                                time="2 minutes ago"
                            />
                            <ActivityItem
                                action="Approval granted"
                                subject="Request #1234"
                                actor="ra@example.com"
                                time="15 minutes ago"
                            />
                            <ActivityItem
                                action="Certificate revoked"
                                subject="CN=old-server.local"
                                actor="admin@example.com"
                                time="1 hour ago"
                            />
                            <ActivityItem
                                action="CRL generated"
                                subject="CRL #567"
                                actor="system"
                                time="2 hours ago"
                            />
                        </ul>
                    </div>
                </div>
            </div>
        </Protected>
    }
}

/// Stat card properties
#[derive(Properties, PartialEq)]
struct StatCardProps {
    title: &'static str,
    value: &'static str,
    change: &'static str,
    positive: bool,
    icon: &'static str,
}

/// Statistics card component
#[function_component(StatCard)]
fn stat_card(props: &StatCardProps) -> Html {
    let change_class = if props.positive {
        "text-green-600"
    } else {
        "text-red-600"
    };

    html! {
        <div class="card">
            <div class="card-body">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-500">{ props.title }</p>
                        <p class="text-2xl font-bold text-gray-900">{ props.value }</p>
                        <p class={classes!("text-sm", change_class)}>{ props.change }</p>
                    </div>
                    <div class="p-3 bg-blue-100 rounded-full">
                        <svg class="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d={props.icon} />
                        </svg>
                    </div>
                </div>
            </div>
        </div>
    }
}

/// Activity item properties
#[derive(Properties, PartialEq)]
struct ActivityItemProps {
    action: &'static str,
    subject: &'static str,
    actor: &'static str,
    time: &'static str,
}

/// Activity item component
#[function_component(ActivityItem)]
fn activity_item(props: &ActivityItemProps) -> Html {
    html! {
        <li class="px-6 py-4 hover:bg-gray-50">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-sm font-medium text-gray-900">{ props.action }</p>
                    <p class="text-sm text-gray-500">{ props.subject }</p>
                </div>
                <div class="text-right">
                    <p class="text-sm text-gray-500">{ props.actor }</p>
                    <p class="text-xs text-gray-400">{ props.time }</p>
                </div>
            </div>
        </li>
    }
}
