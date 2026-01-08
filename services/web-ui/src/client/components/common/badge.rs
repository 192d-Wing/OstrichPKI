//! Badge Component
//!
//! Displays status badges and labels.

use yew::prelude::*;

/// Badge color variants
#[derive(Clone, PartialEq, Default)]
pub enum BadgeVariant {
    #[default]
    Default,
    Primary,
    Success,
    Warning,
    Danger,
    Info,
}

impl BadgeVariant {
    fn class(&self) -> &'static str {
        match self {
            BadgeVariant::Default => "bg-gray-100 text-gray-800",
            BadgeVariant::Primary => "bg-primary-100 text-primary-800",
            BadgeVariant::Success => "bg-green-100 text-green-800",
            BadgeVariant::Warning => "bg-yellow-100 text-yellow-800",
            BadgeVariant::Danger => "bg-red-100 text-red-800",
            BadgeVariant::Info => "bg-blue-100 text-blue-800",
        }
    }
}

/// Badge size variants
#[derive(Clone, PartialEq, Default)]
pub enum BadgeSize {
    Small,
    #[default]
    Medium,
    Large,
}

impl BadgeSize {
    fn class(&self) -> &'static str {
        match self {
            BadgeSize::Small => "px-2 py-0.5 text-xs",
            BadgeSize::Medium => "px-2.5 py-0.5 text-sm",
            BadgeSize::Large => "px-3 py-1 text-sm",
        }
    }
}

/// Properties for the Badge component
#[derive(Properties, Clone, PartialEq)]
pub struct BadgeProps {
    /// Badge text
    pub text: String,

    /// Badge variant/color
    #[prop_or_default]
    pub variant: BadgeVariant,

    /// Badge size
    #[prop_or_default]
    pub size: BadgeSize,

    /// Whether to show a dot indicator
    #[prop_or_default]
    pub dot: bool,

    /// Optional icon (as HTML)
    #[prop_or_default]
    pub icon: Option<Html>,
}

/// Badge component for displaying status labels
#[function_component(Badge)]
pub fn badge(props: &BadgeProps) -> Html {
    let class = format!(
        "inline-flex items-center gap-1 font-medium rounded-full {} {}",
        props.variant.class(),
        props.size.class()
    );

    let dot_class = match props.variant {
        BadgeVariant::Default => "bg-gray-400",
        BadgeVariant::Primary => "bg-primary-400",
        BadgeVariant::Success => "bg-green-400",
        BadgeVariant::Warning => "bg-yellow-400",
        BadgeVariant::Danger => "bg-red-400",
        BadgeVariant::Info => "bg-blue-400",
    };

    html! {
        <span class={class}>
            if props.dot {
                <span class={format!("h-1.5 w-1.5 rounded-full {}", dot_class)} />
            }
            if let Some(icon) = &props.icon {
                {icon.clone()}
            }
            {&props.text}
        </span>
    }
}

/// Status badge helper - maps common statuses to badge variants
pub fn status_badge(status: &str) -> Html {
    let (variant, text) = match status.to_lowercase().as_str() {
        "active" | "valid" | "approved" | "success" => (BadgeVariant::Success, status),
        "pending" | "processing" | "in_progress" => (BadgeVariant::Warning, status),
        "revoked" | "denied" | "failed" | "error" => (BadgeVariant::Danger, status),
        "expired" | "inactive" => (BadgeVariant::Default, status),
        _ => (BadgeVariant::Info, status),
    };

    html! {
        <Badge text={text.to_string()} variant={variant} dot={true} />
    }
}
