//! Pagination Component
//!
//! Displays pagination controls for data tables.

use yew::prelude::*;

/// Properties for the Pagination component
#[derive(Properties, Clone, PartialEq)]
pub struct PaginationProps {
    /// Current page (1-indexed)
    pub current_page: usize,

    /// Total number of pages
    pub total_pages: usize,

    /// Total number of items
    pub total_items: usize,

    /// Items per page
    pub page_size: usize,

    /// Callback when page changes
    pub on_page_change: Callback<usize>,

    /// Whether to show page size selector
    #[prop_or(true)]
    pub show_page_size: bool,

    /// Callback when page size changes
    #[prop_or_default]
    pub on_page_size_change: Option<Callback<usize>>,
}

/// Pagination component
#[function_component(Pagination)]
pub fn pagination(props: &PaginationProps) -> Html {
    let on_page_change = props.on_page_change.clone();
    let current = props.current_page;
    let total = props.total_pages;

    // Calculate range of visible page numbers
    let (start, end) = {
        let max_visible = 5;
        if total <= max_visible {
            (1, total)
        } else if current <= 3 {
            (1, max_visible)
        } else if current >= total - 2 {
            (total - max_visible + 1, total)
        } else {
            (current - 2, current + 2)
        }
    };

    let first_item = (current - 1) * props.page_size + 1;
    let last_item = std::cmp::min(current * props.page_size, props.total_items);

    let page_button = |page: usize| {
        let is_current = page == current;
        let on_click = on_page_change.clone();
        let class = if is_current {
            "relative z-10 inline-flex items-center bg-primary-600 px-4 py-2 text-sm font-semibold text-white focus:z-20 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary-600"
        } else {
            "relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-900 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0"
        };

        html! {
            <button
                type="button"
                class={class}
                onclick={Callback::from(move |_| on_click.emit(page))}
                disabled={is_current}
            >
                {page}
            </button>
        }
    };

    let prev_disabled = current <= 1;
    let next_disabled = current >= total;

    let on_prev = {
        let on_page_change = on_page_change.clone();
        Callback::from(move |_| {
            if current > 1 {
                on_page_change.emit(current - 1);
            }
        })
    };

    let on_next = {
        let on_page_change = on_page_change.clone();
        Callback::from(move |_| {
            if current < total {
                on_page_change.emit(current + 1);
            }
        })
    };

    html! {
        <div class="flex items-center justify-between border-t border-gray-200 bg-white px-4 py-3 sm:px-6">
            // Mobile view
            <div class="flex flex-1 justify-between sm:hidden">
                <button
                    type="button"
                    class="relative inline-flex items-center rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                    onclick={on_prev.clone()}
                    disabled={prev_disabled}
                >
                    {"Previous"}
                </button>
                <button
                    type="button"
                    class="relative ml-3 inline-flex items-center rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                    onclick={on_next.clone()}
                    disabled={next_disabled}
                >
                    {"Next"}
                </button>
            </div>

            // Desktop view
            <div class="hidden sm:flex sm:flex-1 sm:items-center sm:justify-between">
                <div>
                    <p class="text-sm text-gray-700">
                        {"Showing "}
                        <span class="font-medium">{first_item}</span>
                        {" to "}
                        <span class="font-medium">{last_item}</span>
                        {" of "}
                        <span class="font-medium">{props.total_items}</span>
                        {" results"}
                    </p>
                </div>
                <div>
                    <nav class="isolate inline-flex -space-x-px rounded-md shadow-sm" aria-label="Pagination">
                        // Previous button
                        <button
                            type="button"
                            class="relative inline-flex items-center rounded-l-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0 disabled:opacity-50 disabled:cursor-not-allowed"
                            onclick={on_prev}
                            disabled={prev_disabled}
                        >
                            <span class="sr-only">{"Previous"}</span>
                            <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M12.79 5.23a.75.75 0 01-.02 1.06L8.832 10l3.938 3.71a.75.75 0 11-1.04 1.08l-4.5-4.25a.75.75 0 010-1.08l4.5-4.25a.75.75 0 011.06.02z" clip-rule="evenodd"/>
                            </svg>
                        </button>

                        // First page + ellipsis
                        if start > 1 {
                            {page_button(1)}
                            if start > 2 {
                                <span class="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-700 ring-1 ring-inset ring-gray-300">
                                    {"..."}
                                </span>
                            }
                        }

                        // Page numbers
                        { for (start..=end).map(|page| page_button(page)) }

                        // Last page + ellipsis
                        if end < total {
                            if end < total - 1 {
                                <span class="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-gray-700 ring-1 ring-inset ring-gray-300">
                                    {"..."}
                                </span>
                            }
                            {page_button(total)}
                        }

                        // Next button
                        <button
                            type="button"
                            class="relative inline-flex items-center rounded-r-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0 disabled:opacity-50 disabled:cursor-not-allowed"
                            onclick={on_next}
                            disabled={next_disabled}
                        >
                            <span class="sr-only">{"Next"}</span>
                            <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z" clip-rule="evenodd"/>
                            </svg>
                        </button>
                    </nav>
                </div>
            </div>
        </div>
    }
}
