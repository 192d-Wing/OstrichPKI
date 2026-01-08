//! Settings Page

use yew::prelude::*;

use crate::components::auth::Protected;

/// Settings page
#[function_component(Settings)]
pub fn settings() -> Html {
    html! {
        <Protected permission="admin">
            <div class="page-header">
                <h1 class="page-title">{ "Settings" }</h1>
                <p class="page-description">{ "System configuration and preferences" }</p>
            </div>

            <div class="card">
                <div class="card-body">
                    <p class="text-gray-500">{ "Settings interface would be displayed here..." }</p>
                </div>
            </div>
        </Protected>
    }
}
