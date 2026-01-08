//! Login Page

use yew::prelude::*;

/// Login page
#[function_component(Login)]
pub fn login() -> Html {
    let login = Callback::from(|_: MouseEvent| {
        // Redirect to OAuth login endpoint
        if let Some(window) = web_sys::window() {
            let _ = window.location().set_href("/auth/login");
        }
    });

    html! {
        <div class="min-h-screen flex items-center justify-center bg-gray-100">
            <div class="max-w-md w-full">
                <div class="text-center mb-8">
                    <h1 class="text-3xl font-bold text-gray-900">{ "OstrichPKI" }</h1>
                    <p class="mt-2 text-gray-600">{ "Public Key Infrastructure Administration" }</p>
                </div>

                <div class="card">
                    <div class="card-body">
                        <h2 class="text-xl font-semibold text-gray-900 mb-6 text-center">
                            { "Sign in to your account" }
                        </h2>

                        <button
                            onclick={login}
                            class="w-full btn-primary flex items-center justify-center"
                        >
                            <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                    d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" />
                            </svg>
                            { "Sign in with SSO" }
                        </button>

                        <p class="mt-4 text-xs text-gray-500 text-center">
                            { "You will be redirected to your organization's identity provider" }
                        </p>
                    </div>
                </div>

                <p class="mt-4 text-xs text-gray-400 text-center">
                    { format!("Version {}", env!("CARGO_PKG_VERSION")) }
                </p>
            </div>
        </div>
    }
}
