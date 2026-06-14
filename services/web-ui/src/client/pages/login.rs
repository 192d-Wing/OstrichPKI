//! Login Page
//!
//! Internal-auth login form: posts the admin's credentials to
//! `/auth/internal-login`, which the server validates against the CA's own
//! account store (argon2id + RBAC) — no external identity provider. A fallback
//! SSO link is shown for deployments still running in OIDC mode.

use gloo_net::http::Request;
use serde_json::json;
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlInputElement;
use yew::prelude::*;

/// Login page
#[function_component(Login)]
pub fn login() -> Html {
    let username = use_state(String::new);
    let password = use_state(String::new);
    let error = use_state(|| Option::<String>::None);
    let submitting = use_state(|| false);

    let on_user = {
        let username = username.clone();
        Callback::from(move |e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            username.set(input.value());
        })
    };
    let on_pass = {
        let password = password.clone();
        Callback::from(move |e: InputEvent| {
            let input: HtmlInputElement = e.target_unchecked_into();
            password.set(input.value());
        })
    };

    let on_submit = {
        let username = username.clone();
        let password = password.clone();
        let error = error.clone();
        let submitting = submitting.clone();
        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            let (u, p) = ((*username).clone(), (*password).clone());
            let error = error.clone();
            let submitting = submitting.clone();
            submitting.set(true);
            error.set(None);
            spawn_local(async move {
                let req = Request::post("/auth/internal-login")
                    .json(&json!({ "username": u, "password": p }));
                match req {
                    Ok(req) => match req.send().await {
                        Ok(resp) if resp.ok() => {
                            if let Some(window) = web_sys::window() {
                                let _ = window.location().set_href("/");
                            }
                        }
                        Ok(resp) if resp.status() == 401 => {
                            error.set(Some("Invalid username or password".to_string()));
                            submitting.set(false);
                        }
                        Ok(resp) => {
                            error.set(Some(format!("Login failed (HTTP {})", resp.status())));
                            submitting.set(false);
                        }
                        Err(e) => {
                            error.set(Some(format!("Network error: {e}")));
                            submitting.set(false);
                        }
                    },
                    Err(e) => {
                        error.set(Some(format!("Request error: {e}")));
                        submitting.set(false);
                    }
                }
            });
        })
    };

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

                        if let Some(msg) = (*error).clone() {
                            <div class="mb-4 rounded bg-red-50 border border-red-200 text-red-700 px-3 py-2 text-sm">
                                { msg }
                            </div>
                        }

                        <form onsubmit={on_submit}>
                            <label class="block text-sm font-medium text-gray-700 mb-1">{ "Username" }</label>
                            <input
                                type="text"
                                class="w-full mb-4 px-3 py-2 border border-gray-300 rounded focus:outline-none focus:ring focus:border-blue-400"
                                value={(*username).clone()}
                                oninput={on_user}
                                autocomplete="username"
                                required=true
                            />

                            <label class="block text-sm font-medium text-gray-700 mb-1">{ "Password" }</label>
                            <input
                                type="password"
                                class="w-full mb-6 px-3 py-2 border border-gray-300 rounded focus:outline-none focus:ring focus:border-blue-400"
                                value={(*password).clone()}
                                oninput={on_pass}
                                autocomplete="current-password"
                                required=true
                            />

                            <button
                                type="submit"
                                disabled={*submitting}
                                class="w-full btn-primary flex items-center justify-center disabled:opacity-60"
                            >
                                { if *submitting { "Signing in…" } else { "Sign in" } }
                            </button>
                        </form>

                    </div>
                </div>

                <p class="mt-4 text-xs text-gray-400 text-center">
                    { format!("Version {}", env!("CARGO_PKG_VERSION")) }
                </p>
            </div>
        </div>
    }
}
