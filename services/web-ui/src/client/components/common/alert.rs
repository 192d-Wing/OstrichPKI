//! Alert/Notification Component
//!
//! Displays alert messages with different severity levels.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SI-11 (Error Handling) - User-friendly error messages

use yew::prelude::*;

/// Alert type/severity variants
#[derive(Clone, PartialEq, Default)]
pub enum AlertType {
    #[default]
    Info,
    Success,
    Warning,
    Error,
}

impl AlertType {
    fn container_class(&self) -> &'static str {
        match self {
            AlertType::Info => "bg-blue-50 border-blue-200 text-blue-800",
            AlertType::Success => "bg-green-50 border-green-200 text-green-800",
            AlertType::Warning => "bg-yellow-50 border-yellow-200 text-yellow-800",
            AlertType::Error => "bg-red-50 border-red-200 text-red-800",
        }
    }

    fn icon_class(&self) -> &'static str {
        match self {
            AlertType::Info => "text-blue-500",
            AlertType::Success => "text-green-500",
            AlertType::Warning => "text-yellow-500",
            AlertType::Error => "text-red-500",
        }
    }
}

/// Properties for the Alert component
#[derive(Properties, Clone, PartialEq)]
pub struct AlertProps {
    /// The alert message (used when no children are provided).
    #[prop_or_default]
    pub message: Option<String>,

    /// Child content, rendered instead of `message` when present.
    #[prop_or_default]
    pub children: Html,

    /// Alert type/severity
    #[prop_or_default]
    pub alert_type: AlertType,

    /// Optional title
    #[prop_or_default]
    pub title: Option<String>,

    /// Whether the alert can be dismissed
    #[prop_or_default]
    pub dismissible: bool,

    /// Callback when dismissed
    #[prop_or_default]
    pub on_dismiss: Option<Callback<()>>,
}

/// Alert component for displaying notifications
#[function_component(Alert)]
pub fn alert(props: &AlertProps) -> Html {
    let container_class = format!(
        "rounded-lg border p-4 {}",
        props.alert_type.container_class()
    );

    let icon = match props.alert_type {
        AlertType::Info => html! {
            <svg class={format!("h-5 w-5 {}", props.alert_type.icon_class())} viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"/>
            </svg>
        },
        AlertType::Success => html! {
            <svg class={format!("h-5 w-5 {}", props.alert_type.icon_class())} viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
            </svg>
        },
        AlertType::Warning => html! {
            <svg class={format!("h-5 w-5 {}", props.alert_type.icon_class())} viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/>
            </svg>
        },
        AlertType::Error => html! {
            <svg class={format!("h-5 w-5 {}", props.alert_type.icon_class())} viewBox="0 0 20 20" fill="currentColor">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"/>
            </svg>
        },
    };

    let on_dismiss = props.on_dismiss.clone();

    html! {
        <div class={container_class} role="alert">
            <div class="flex">
                <div class="flex-shrink-0">
                    {icon}
                </div>
                <div class="ml-3 flex-1">
                    if let Some(title) = &props.title {
                        <h3 class="text-sm font-medium">{title}</h3>
                    }
                    <div class={if props.title.is_some() { "mt-1 text-sm" } else { "text-sm" }}>
                        if props.children != Html::default() {
                            { props.children.clone() }
                        } else if let Some(message) = &props.message {
                            { message }
                        }
                    </div>
                </div>
                if props.dismissible {
                    <div class="ml-auto pl-3">
                        <button
                            type="button"
                            class="inline-flex rounded-md p-1.5 hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-offset-2"
                            onclick={Callback::from(move |_| {
                                if let Some(cb) = &on_dismiss {
                                    cb.emit(());
                                }
                            })}
                        >
                            <span class="sr-only">{"Dismiss"}</span>
                            <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/>
                            </svg>
                        </button>
                    </div>
                }
            </div>
        </div>
    }
}
