//! Modal/Dialog Component
//!
//! Displays modal dialogs for confirmations, forms, and information.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-3 (Access Enforcement) - Confirmation dialogs for sensitive actions

use yew::prelude::*;

/// Modal size variants
#[derive(Clone, PartialEq, Default)]
pub enum ModalSize {
    Small,
    #[default]
    Medium,
    Large,
    XLarge,
}

impl ModalSize {
    fn class(&self) -> &'static str {
        match self {
            ModalSize::Small => "max-w-md",
            ModalSize::Medium => "max-w-lg",
            ModalSize::Large => "max-w-2xl",
            ModalSize::XLarge => "max-w-4xl",
        }
    }
}

/// Properties for the Modal component
#[derive(Properties, Clone, PartialEq)]
pub struct ModalProps {
    /// Whether the modal is visible
    pub open: bool,

    /// Modal title
    pub title: String,

    /// Modal content
    pub children: Children,

    /// Callback when modal is closed
    pub on_close: Callback<()>,

    /// Modal size
    #[prop_or_default]
    pub size: ModalSize,

    /// Whether clicking backdrop closes modal
    #[prop_or(true)]
    pub close_on_backdrop: bool,

    /// Optional footer content
    #[prop_or_default]
    pub footer: Option<Html>,
}

/// Modal dialog component
#[function_component(Modal)]
pub fn modal(props: &ModalProps) -> Html {
    let on_close = props.on_close.clone();
    let close_on_backdrop = props.close_on_backdrop;

    let on_backdrop_click = {
        let on_close = on_close.clone();
        Callback::from(move |_| {
            if close_on_backdrop {
                on_close.emit(());
            }
        })
    };

    let on_content_click = Callback::from(|e: MouseEvent| {
        e.stop_propagation();
    });

    if !props.open {
        return html! {};
    }

    let modal_class = format!(
        "relative bg-white rounded-lg shadow-xl w-full {} mx-4",
        props.size.class()
    );

    html! {
        <div
            class="fixed inset-0 z-50 overflow-y-auto"
            aria-labelledby="modal-title"
            role="dialog"
            aria-modal="true"
        >
            // Backdrop
            <div
                class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity"
                onclick={on_backdrop_click}
            />

            // Modal container
            <div class="flex min-h-full items-center justify-center p-4">
                <div class={modal_class} onclick={on_content_click}>
                    // Header
                    <div class="flex items-center justify-between px-6 py-4 border-b border-gray-200">
                        <h3 class="text-lg font-semibold text-gray-900" id="modal-title">
                            {&props.title}
                        </h3>
                        <button
                            type="button"
                            class="rounded-md text-gray-400 hover:text-gray-500 focus:outline-none focus:ring-2 focus:ring-primary-500"
                            onclick={Callback::from({
                                let on_close = on_close.clone();
                                move |_| on_close.emit(())
                            })}
                        >
                            <span class="sr-only">{"Close"}</span>
                            <svg class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
                            </svg>
                        </button>
                    </div>

                    // Body
                    <div class="px-6 py-4">
                        {for props.children.iter()}
                    </div>

                    // Footer
                    if let Some(footer) = &props.footer {
                        <div class="flex items-center justify-end gap-3 px-6 py-4 border-t border-gray-200 bg-gray-50">
                            {footer.clone()}
                        </div>
                    }
                </div>
            </div>
        </div>
    }
}

/// Confirmation modal properties
#[derive(Properties, Clone, PartialEq)]
pub struct ConfirmModalProps {
    /// Whether the modal is visible
    pub open: bool,

    /// Modal title
    pub title: String,

    /// Confirmation message
    pub message: String,

    /// Confirm button text
    #[prop_or("Confirm".to_string())]
    pub confirm_text: String,

    /// Cancel button text
    #[prop_or("Cancel".to_string())]
    pub cancel_text: String,

    /// Whether this is a destructive action
    #[prop_or_default]
    pub destructive: bool,

    /// Loading state
    #[prop_or_default]
    pub loading: bool,

    /// Callback when confirmed
    pub on_confirm: Callback<()>,

    /// Callback when cancelled
    pub on_cancel: Callback<()>,
}

/// Confirmation modal component
#[function_component(ConfirmModal)]
pub fn confirm_modal(props: &ConfirmModalProps) -> Html {
    let confirm_class = if props.destructive {
        "btn btn-danger"
    } else {
        "btn btn-primary"
    };

    let on_confirm = props.on_confirm.clone();
    let on_cancel = props.on_cancel.clone();
    let loading = props.loading;

    let footer = html! {
        <>
            <button
                type="button"
                class="btn btn-secondary"
                onclick={Callback::from(move |_| on_cancel.emit(()))}
                disabled={loading}
            >
                {&props.cancel_text}
            </button>
            <button
                type="button"
                class={confirm_class}
                onclick={Callback::from(move |_| on_confirm.emit(()))}
                disabled={loading}
            >
                if loading {
                    <svg class="animate-spin -ml-1 mr-2 h-4 w-4" fill="none" viewBox="0 0 24 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/>
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"/>
                    </svg>
                }
                {&props.confirm_text}
            </button>
        </>
    };

    html! {
        <Modal
            open={props.open}
            title={props.title.clone()}
            on_close={props.on_cancel.clone()}
            size={ModalSize::Small}
            footer={Some(footer)}
        >
            <p class="text-gray-600">{&props.message}</p>
        </Modal>
    }
}
