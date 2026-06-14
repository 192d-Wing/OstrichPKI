//! Root Application Component
//!
//! The main Yew application component that sets up:
//! - Client-side routing
//! - Authentication context
//! - Layout structure

use yew::prelude::*;
use yew_router::prelude::*;

use crate::components::layout::{Navbar, Sidebar};
use crate::pages;
use crate::router::Route;
use crate::services::auth::AuthProvider;

/// Root application component
#[function_component(App)]
pub fn app() -> Html {
    html! {
        <BrowserRouter>
            <AuthProvider>
                <AppLayout />
            </AuthProvider>
        </BrowserRouter>
    }
}

/// Application layout component
#[function_component(AppLayout)]
fn app_layout() -> Html {
    html! {
        <div class="flex h-screen bg-gray-100">
            // Sidebar navigation
            <Sidebar />

            // Main content area
            <div class="flex-1 flex flex-col overflow-hidden ml-64">
                // Top navigation bar
                <Navbar />

                // Page content
                <main class="flex-1 overflow-y-auto p-6 scrollbar-thin">
                    <Switch<Route> render={switch_route} />
                </main>
            </div>
        </div>
    }
}

/// Route switch function
fn switch_route(route: Route) -> Html {
    // Hide loading indicator when app renders
    hide_loading_indicator();

    match route {
        Route::Dashboard => html! { <pages::Dashboard /> },
        Route::Certificates => html! { <pages::Certificates /> },
        Route::CertificateIssue => html! { <pages::CertificateIssue /> },
        Route::CertificateDetail { id } => html! { <pages::CertificateDetail {id} /> },
        Route::Approvals => html! { <pages::Approvals /> },
        Route::AuditLogs => html! { <pages::AuditLogs /> },
        Route::Scms => html! { <pages::Scms /> },
        Route::Users => html! { <pages::Users /> },
        Route::Settings => html! { <pages::Settings /> },
        Route::Login => html! { <pages::Login /> },
        Route::NotFound => html! { <pages::NotFound /> },
    }
}

/// Hide the loading indicator after the app mounts
fn hide_loading_indicator() {
    if let Some(window) = web_sys::window() {
        if let Some(document) = window.document() {
            if let Some(loading) = document.get_element_by_id("loading") {
                let _ = loading.set_attribute("style", "display: none;");
            }
        }
    }
}
