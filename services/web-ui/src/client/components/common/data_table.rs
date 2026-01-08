//! DataTable Component
//!
//! Generic sortable, filterable data table component.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-6 (Audit Review) - Tabular data display for audit logs

use std::rc::Rc;
use yew::prelude::*;

use super::loading::Loading;
use super::pagination::Pagination;

/// Sort direction
#[derive(Clone, PartialEq, Default)]
pub enum SortDirection {
    #[default]
    None,
    Ascending,
    Descending,
}

/// Column definition for the data table
#[derive(Clone)]
pub struct Column<T: Clone + PartialEq + 'static> {
    /// Column header text
    pub header: String,

    /// Unique key for the column
    pub key: String,

    /// Whether the column is sortable
    pub sortable: bool,

    /// Column width class (e.g., "w-32", "w-48")
    pub width: Option<String>,

    /// Cell renderer function
    pub render: Rc<dyn Fn(&T) -> Html>,
}

impl<T: Clone + PartialEq + 'static> PartialEq for Column<T> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.header == other.header
    }
}

/// Properties for the DataTable component
#[derive(Properties, Clone, PartialEq)]
pub struct DataTableProps<T: Clone + PartialEq + 'static> {
    /// Table data
    pub data: Vec<T>,

    /// Column definitions
    pub columns: Vec<Column<T>>,

    /// Whether data is loading
    #[prop_or_default]
    pub loading: bool,

    /// Current sort column key
    #[prop_or_default]
    pub sort_by: Option<String>,

    /// Current sort direction
    #[prop_or_default]
    pub sort_direction: SortDirection,

    /// Callback when sort changes
    #[prop_or_default]
    pub on_sort: Option<Callback<(String, SortDirection)>>,

    /// Whether to show row hover effect
    #[prop_or(true)]
    pub hoverable: bool,

    /// Row click handler
    #[prop_or_default]
    pub on_row_click: Option<Callback<T>>,

    /// Empty state message
    #[prop_or("No data available".to_string())]
    pub empty_message: String,

    /// Current page (1-indexed, for pagination)
    #[prop_or(1)]
    pub current_page: usize,

    /// Total number of items (for pagination)
    #[prop_or_default]
    pub total_items: usize,

    /// Items per page
    #[prop_or(10)]
    pub page_size: usize,

    /// Callback when page changes
    #[prop_or_default]
    pub on_page_change: Option<Callback<usize>>,

    /// Whether to show pagination
    #[prop_or(true)]
    pub show_pagination: bool,
}

/// Generic data table component
#[function_component(DataTable)]
pub fn data_table<T: Clone + PartialEq + 'static>(props: &DataTableProps<T>) -> Html {
    let row_class = if props.hoverable && props.on_row_click.is_some() {
        "hover:bg-gray-50 cursor-pointer"
    } else if props.hoverable {
        "hover:bg-gray-50"
    } else {
        ""
    };

    let total_pages = if props.page_size > 0 && props.total_items > 0 {
        (props.total_items + props.page_size - 1) / props.page_size
    } else {
        1
    };

    html! {
        <div class="overflow-hidden shadow ring-1 ring-black ring-opacity-5 rounded-lg">
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-300">
                    <thead class="bg-gray-50">
                        <tr>
                            { for props.columns.iter().map(|col| {
                                let width_class = col.width.clone().unwrap_or_default();
                                let header_class = format!(
                                    "px-3 py-3.5 text-left text-sm font-semibold text-gray-900 {}",
                                    width_class
                                );

                                if col.sortable {
                                    let is_sorted = props.sort_by.as_ref() == Some(&col.key);
                                    let direction = if is_sorted {
                                        props.sort_direction.clone()
                                    } else {
                                        SortDirection::None
                                    };

                                    let on_sort = props.on_sort.clone();
                                    let key = col.key.clone();
                                    let next_direction = match direction {
                                        SortDirection::None | SortDirection::Descending => SortDirection::Ascending,
                                        SortDirection::Ascending => SortDirection::Descending,
                                    };

                                    html! {
                                        <th scope="col" class={header_class}>
                                            <button
                                                type="button"
                                                class="group inline-flex items-center gap-1"
                                                onclick={Callback::from(move |_| {
                                                    if let Some(cb) = &on_sort {
                                                        cb.emit((key.clone(), next_direction.clone()));
                                                    }
                                                })}
                                            >
                                                {&col.header}
                                                <span class={if is_sorted { "text-gray-900" } else { "text-gray-400 group-hover:text-gray-500" }}>
                                                    {match direction {
                                                        SortDirection::Ascending => html! {
                                                            <svg class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                                                                <path fill-rule="evenodd" d="M10 17a.75.75 0 01-.75-.75V5.612L5.29 9.77a.75.75 0 01-1.08-1.04l5.25-5.5a.75.75 0 011.08 0l5.25 5.5a.75.75 0 11-1.08 1.04l-3.96-4.158V16.25A.75.75 0 0110 17z" clip-rule="evenodd"/>
                                                            </svg>
                                                        },
                                                        SortDirection::Descending => html! {
                                                            <svg class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                                                                <path fill-rule="evenodd" d="M10 3a.75.75 0 01.75.75v10.638l3.96-4.158a.75.75 0 111.08 1.04l-5.25 5.5a.75.75 0 01-1.08 0l-5.25-5.5a.75.75 0 111.08-1.04l3.96 4.158V3.75A.75.75 0 0110 3z" clip-rule="evenodd"/>
                                                            </svg>
                                                        },
                                                        SortDirection::None => html! {
                                                            <svg class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                                                                <path fill-rule="evenodd" d="M10 3a.75.75 0 01.53.22l3.25 3.25a.75.75 0 01-1.06 1.06L10 4.81 7.28 7.53a.75.75 0 01-1.06-1.06l3.25-3.25A.75.75 0 0110 3zm-3.72 9.47a.75.75 0 011.06 0L10 15.19l2.72-2.72a.75.75 0 111.06 1.06l-3.25 3.25a.75.75 0 01-1.06 0l-3.25-3.25a.75.75 0 010-1.06z" clip-rule="evenodd"/>
                                                            </svg>
                                                        },
                                                    }}
                                                </span>
                                            </button>
                                        </th>
                                    }
                                } else {
                                    html! {
                                        <th scope="col" class={header_class}>
                                            {&col.header}
                                        </th>
                                    }
                                }
                            })}
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200 bg-white">
                        if props.loading {
                            <tr>
                                <td colspan={props.columns.len().to_string()} class="px-3 py-8">
                                    <Loading message={Some("Loading data...".to_string())} />
                                </td>
                            </tr>
                        } else if props.data.is_empty() {
                            <tr>
                                <td colspan={props.columns.len().to_string()} class="px-3 py-8 text-center text-gray-500">
                                    {&props.empty_message}
                                </td>
                            </tr>
                        } else {
                            { for props.data.iter().map(|row| {
                                let on_click = props.on_row_click.clone();
                                let row_data = row.clone();

                                html! {
                                    <tr
                                        class={row_class}
                                        onclick={Callback::from(move |_| {
                                            if let Some(cb) = &on_click {
                                                cb.emit(row_data.clone());
                                            }
                                        })}
                                    >
                                        { for props.columns.iter().map(|col| {
                                            html! {
                                                <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">
                                                    {(col.render)(row)}
                                                </td>
                                            }
                                        })}
                                    </tr>
                                }
                            })}
                        }
                    </tbody>
                </table>
            </div>

            if props.show_pagination && props.total_items > 0 && !props.loading {
                if let Some(on_page_change) = &props.on_page_change {
                    <Pagination
                        current_page={props.current_page}
                        total_pages={total_pages}
                        total_items={props.total_items}
                        page_size={props.page_size}
                        on_page_change={on_page_change.clone()}
                    />
                }
            }
        </div>
    }
}
