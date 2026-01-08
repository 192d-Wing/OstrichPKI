//! Protected Route Component
//!
//! Wraps content that requires authentication and/or specific permissions.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-3 (Access Enforcement)
//! - NIAP PP-CA: FDP_ACC.1 (Access Control Policy)

use yew::prelude::*;
use yew_router::prelude::*;

use crate::router::Route;
use crate::services::auth::use_auth;

/// Props for the Protected component
#[derive(Properties, PartialEq)]
pub struct ProtectedProps {
    /// Optional permission required to view this content
    #[prop_or_default]
    pub permission: Option<String>,

    /// Child content to display if authorized
    pub children: Children,
}

/// Protected route component
///
/// Redirects to login if not authenticated, or shows access denied if missing permission.
#[function_component(Protected)]
pub fn protected(props: &ProtectedProps) -> Html {
    let auth = use_auth();
    let navigator = use_navigator().expect("Navigator not available");

    // Check authentication
    if !auth.is_authenticated() {
        // Redirect to login
        navigator.push(&Route::Login);
        return html! {
            <div class="flex items-center justify-center h-64">
                <div class="text-center">
                    <div class="inline-block animate-spin rounded-full h-8 w-8 border-4 border-blue-600 border-t-transparent"></div>
                    <p class="mt-2 text-gray-600">{"Redirecting to login..."}</p>
                </div>
            </div>
        };
    }

    // Check permission if specified
    if let Some(ref permission) = props.permission {
        if !auth.has_permission(permission) {
            return html! {
                <div class="card max-w-md mx-auto mt-8">
                    <div class="card-body text-center">
                        // Access denied icon
                        <div class="mx-auto w-16 h-16 rounded-full bg-red-100 flex items-center justify-center mb-4">
                            <svg class="w-8 h-8 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                    d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                            </svg>
                        </div>

                        <h2 class="text-xl font-bold text-gray-900 mb-2">
                            { "Access Denied" }
                        </h2>

                        <p class="text-gray-600 mb-4">
                            { "You do not have permission to access this page." }
                        </p>

                        <p class="text-sm text-gray-500 mb-4">
                            { format!("Required permission: {}", permission) }
                        </p>

                        <Link<Route> to={Route::Dashboard} classes="btn-primary">
                            { "Return to Dashboard" }
                        </Link<Route>>
                    </div>
                </div>
            };
        }
    }

    // Authorized - render children
    html! {
        <>{ for props.children.iter() }</>
    }
}
