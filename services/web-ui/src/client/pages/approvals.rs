//! Approval Queue Page

use yew::prelude::*;

use crate::components::auth::Protected;

/// Approvals page
#[function_component(Approvals)]
pub fn approvals() -> Html {
    html! {
        <Protected permission="view_approvals">
            <div class="page-header">
                <h1 class="page-title">{ "Approval Queue" }</h1>
                <p class="page-description">{ "Review and approve certificate requests" }</p>
            </div>

            <div class="card">
                <div class="card-body">
                    <p class="text-gray-500">{ "Approval queue would be displayed here..." }</p>
                </div>
            </div>
        </Protected>
    }
}
