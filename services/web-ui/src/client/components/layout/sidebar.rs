//! Sidebar Navigation Component

use yew::prelude::*;
use yew_router::prelude::*;

use crate::router::Route;
use crate::services::auth::use_auth;

/// Navigation item for the sidebar
struct NavItem {
    route: Route,
    label: &'static str,
    icon: &'static str,
    permission: Option<&'static str>,
}

/// Sidebar navigation component
#[function_component(Sidebar)]
pub fn sidebar() -> Html {
    let auth = use_auth();
    let current_route = use_route::<Route>();

    // Define navigation items
    let nav_items = vec![
        NavItem {
            route: Route::Dashboard,
            label: "Dashboard",
            icon: "M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6",
            permission: None,
        },
        NavItem {
            route: Route::Certificates,
            label: "Certificates",
            icon: "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z",
            permission: Some("view_certificates"),
        },
        NavItem {
            route: Route::Crl,
            label: "Revocation Lists",
            icon: "M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636",
            permission: Some("view_crl"),
        },
        NavItem {
            route: Route::Profiles,
            label: "Profiles",
            icon: "M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10",
            permission: Some("view_config"),
        },
        NavItem {
            route: Route::Approvals,
            label: "Approvals",
            icon: "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4",
            permission: Some("view_approvals"),
        },
        NavItem {
            route: Route::AuditLogs,
            label: "Audit Logs",
            icon: "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01",
            permission: Some("read_audit_log"),
        },
        NavItem {
            route: Route::Scms,
            label: "Tokens",
            icon: "M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z",
            permission: Some("view_tokens"),
        },
        NavItem {
            route: Route::Users,
            label: "Users",
            icon: "M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z",
            permission: Some("manage_users"),
        },
        NavItem {
            route: Route::Settings,
            label: "Settings",
            icon: "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z",
            permission: Some("admin"),
        },
    ];

    html! {
        <aside class="sidebar">
            // Logo/Brand
            <div class="flex items-center justify-center h-16 border-b border-gray-800">
                <span class="text-xl font-bold text-white">{"OstrichPKI"}</span>
            </div>

            // Navigation
            <nav class="mt-4">
                { for nav_items.iter().filter_map(|item| {
                    // Check permission
                    if let Some(perm) = item.permission {
                        if !auth.has_permission(perm) {
                            return None;
                        }
                    }

                    let is_active = current_route.as_ref() == Some(&item.route);
                    let class = if is_active {
                        "sidebar-link-active"
                    } else {
                        "sidebar-link"
                    };

                    Some(html! {
                        <Link<Route> to={item.route.clone()} classes={classes!(class)}>
                            <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d={item.icon} />
                            </svg>
                            { item.label }
                        </Link<Route>>
                    })
                })}
            </nav>

            // Footer with version
            <div class="absolute bottom-0 left-0 right-0 p-4 border-t border-gray-800">
                <p class="text-xs text-gray-500 text-center">
                    { format!("v{}", env!("CARGO_PKG_VERSION")) }
                </p>
            </div>
        </aside>
    }
}
