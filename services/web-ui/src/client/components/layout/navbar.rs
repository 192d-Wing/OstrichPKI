//! Top Navigation Bar Component

use yew::prelude::*;

use crate::services::auth::use_auth;

/// Top navigation bar component
#[function_component(Navbar)]
pub fn navbar() -> Html {
    let auth = use_auth();
    let show_dropdown = use_state(|| false);

    let toggle_dropdown = {
        let show_dropdown = show_dropdown.clone();
        Callback::from(move |_: MouseEvent| {
            show_dropdown.set(!*show_dropdown);
        })
    };

    let logout = {
        let auth = auth.clone();
        Callback::from(move |_: MouseEvent| {
            auth.logout();
        })
    };

    let logout_all = {
        let auth = auth.clone();
        Callback::from(move |_: MouseEvent| {
            auth.logout_everywhere();
        })
    };

    html! {
        <header class="navbar flex items-center justify-between">
            // Left side - Page title / breadcrumbs
            <div class="flex items-center">
                <h1 class="text-lg font-semibold text-gray-900">
                    { "Administration" }
                </h1>
            </div>

            // Right side - User menu
            <div class="flex items-center space-x-4">
                // Notifications (placeholder)
                <button
                    type="button"
                    class="p-2 text-gray-500 hover:text-gray-700 rounded-full hover:bg-gray-100"
                    title="Notifications"
                >
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                            d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
                    </svg>
                </button>

                // User dropdown
                <div class="relative">
                    <button
                        type="button"
                        onclick={toggle_dropdown}
                        class="flex items-center space-x-2 p-2 rounded-md hover:bg-gray-100"
                    >
                        // User avatar
                        <div class="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-white font-medium">
                            { auth.user().map(|u| u.username.chars().next().unwrap_or('U').to_uppercase().to_string()).unwrap_or_else(|| "U".to_string()) }
                        </div>
                        // User name
                        <span class="text-sm font-medium text-gray-700">
                            { auth.user().map(|u| u.username.clone()).unwrap_or_else(|| "User".to_string()) }
                        </span>
                        // Dropdown arrow
                        <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                        </svg>
                    </button>

                    // Dropdown menu
                    if *show_dropdown {
                        <div class="absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg py-1 z-50 border border-gray-200 animate-fade-in">
                            // User info
                            <div class="px-4 py-2 border-b border-gray-100">
                                <p class="text-sm font-medium text-gray-900">
                                    { auth.user().map(|u| u.username.clone()).unwrap_or_default() }
                                </p>
                                <p class="text-xs text-gray-500">
                                    { auth.user().and_then(|u| u.email.clone()).unwrap_or_default() }
                                </p>
                            </div>

                            // Menu items
                            <a
                                href="/settings"
                                class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
                            >
                                { "Settings" }
                            </a>
                            <button
                                type="button"
                                onclick={logout}
                                class="w-full text-left px-4 py-2 text-sm text-red-600 hover:bg-gray-100"
                            >
                                { "Sign out" }
                            </button>
                            <button
                                type="button"
                                onclick={logout_all}
                                class="w-full text-left px-4 py-2 text-sm text-red-600 hover:bg-gray-100"
                                title="End all of your sessions on every device"
                            >
                                { "Sign out everywhere" }
                            </button>
                        </div>
                    }
                </div>
            </div>
        </header>
    }
}
