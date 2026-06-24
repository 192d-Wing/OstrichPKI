//! Copy-to-clipboard button.
//!
//! A small button that copies its `text` to the clipboard (the async Clipboard
//! API, available in secure contexts — the UI is served over HTTPS) and briefly
//! shows "Copied" feedback, like the copy control on a Markdown code block.

use gloo_timers::callback::Timeout;
use wasm_bindgen_futures::{JsFuture, spawn_local};
use yew::prelude::*;

/// Props for [`CopyButton`].
#[derive(Properties, PartialEq)]
pub struct CopyButtonProps {
    /// The text placed on the clipboard when clicked.
    pub text: String,
    /// Extra classes for positioning (e.g. absolute placement over a block).
    #[prop_or_default]
    pub class: Classes,
}

/// A button that copies [`CopyButtonProps::text`] to the clipboard.
#[function_component(CopyButton)]
pub fn copy_button(props: &CopyButtonProps) -> Html {
    let copied = use_state(|| false);

    let onclick = {
        let text = props.text.clone();
        let copied = copied.clone();
        Callback::from(move |_: MouseEvent| {
            let text = text.clone();
            let copied = copied.clone();
            spawn_local(async move {
                // Write to the clipboard; on success (or failure) we still flash
                // feedback so the operator isn't left wondering.
                if let Some(win) = web_sys::window() {
                    let promise = win.navigator().clipboard().write_text(&text);
                    let _ = JsFuture::from(promise).await;
                }
                copied.set(true);
                // Revert the "Copied" label after a short delay.
                let reset = copied.clone();
                Timeout::new(1500, move || reset.set(false)).forget();
            });
        })
    };

    let base = "inline-flex items-center gap-1 rounded border border-gray-300 bg-white \
                px-2 py-1 text-xs font-medium text-gray-600 shadow-sm hover:bg-gray-50 \
                focus:outline-none focus:ring-2 focus:ring-primary-500";

    html! {
        <button type="button" onclick={onclick}
                class={classes!(base, props.class.clone())}
                title="Copy to clipboard">
            { if *copied {
                html! { <><span aria-hidden="true">{ "✓" }</span>{ "Copied" }</> }
              } else {
                html! { <><span aria-hidden="true">{ "⧉" }</span>{ "Copy" }</> }
              } }
        </button>
    }
}
