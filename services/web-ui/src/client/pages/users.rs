//! User Management Page

use yew::prelude::*;

use crate::components::auth::Protected;

/// User management page
#[function_component(Users)]
pub fn users() -> Html {
    html! {
        <Protected permission="manage_users">
            <div class="page-header">
                <h1 class="page-title">{ "User Management" }</h1>
                <p class="page-description">{ "Manage users and role assignments" }</p>
            </div>

            <div class="card">
                <div class="card-body">
                    <p class="text-gray-500">{ "User management interface would be displayed here..." }</p>
                </div>
            </div>
        </Protected>
    }
}
