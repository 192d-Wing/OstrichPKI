//! SCMS Token Management Page

use yew::prelude::*;

use crate::components::auth::Protected;

/// SCMS token management page
#[function_component(Scms)]
pub fn scms() -> Html {
    html! {
        <Protected permission="view_tokens">
            <div class="page-header">
                <h1 class="page-title">{ "Token Management" }</h1>
                <p class="page-description">{ "Manage smartcards and security tokens" }</p>
            </div>

            <div class="card">
                <div class="card-body">
                    <p class="text-gray-500">{ "Token management interface would be displayed here..." }</p>
                </div>
            </div>
        </Protected>
    }
}
