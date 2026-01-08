//! Loading Spinner Component
//!
//! Displays a loading indicator during async operations.

use yew::prelude::*;

/// Loading spinner size variants
#[derive(Clone, PartialEq, Default)]
pub enum LoadingSize {
    Small,
    #[default]
    Medium,
    Large,
}

impl LoadingSize {
    fn class(&self) -> &'static str {
        match self {
            LoadingSize::Small => "h-4 w-4",
            LoadingSize::Medium => "h-8 w-8",
            LoadingSize::Large => "h-12 w-12",
        }
    }
}

/// Properties for the Loading component
#[derive(Properties, Clone, PartialEq)]
pub struct LoadingProps {
    /// Optional message to display below the spinner
    #[prop_or_default]
    pub message: Option<String>,

    /// Size of the spinner
    #[prop_or_default]
    pub size: LoadingSize,

    /// Whether to center in the container
    #[prop_or(true)]
    pub centered: bool,

    /// Whether to show as a full-page overlay
    #[prop_or_default]
    pub overlay: bool,
}

/// Loading spinner component
#[function_component(Loading)]
pub fn loading(props: &LoadingProps) -> Html {
    let spinner_class = format!(
        "{} animate-spin text-primary-600",
        props.size.class()
    );

    let container_class = if props.overlay {
        "fixed inset-0 bg-gray-900/50 flex items-center justify-center z-50"
    } else if props.centered {
        "flex flex-col items-center justify-center py-8"
    } else {
        "inline-flex items-center gap-2"
    };

    html! {
        <div class={container_class}>
            <svg
                class={spinner_class}
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
            >
                <circle
                    class="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    stroke-width="4"
                />
                <path
                    class="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                />
            </svg>
            if let Some(message) = &props.message {
                <p class="mt-2 text-sm text-gray-600">{message}</p>
            }
        </div>
    }
}
