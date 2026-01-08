//! 404 Not Found Page

use yew::prelude::*;
use yew_router::prelude::*;

use crate::router::Route;

/// 404 Not Found page
#[function_component(NotFound)]
pub fn not_found() -> Html {
    html! {
        <div class="min-h-[60vh] flex items-center justify-center">
            <div class="text-center">
                <h1 class="text-6xl font-bold text-gray-300">{ "404" }</h1>
                <h2 class="mt-4 text-2xl font-semibold text-gray-900">{ "Page Not Found" }</h2>
                <p class="mt-2 text-gray-600">{ "The page you're looking for doesn't exist." }</p>
                <Link<Route> to={Route::Dashboard} classes="btn-primary inline-block mt-6">
                    { "Return to Dashboard" }
                </Link<Route>>
            </div>
        </div>
    }
}
