//! Approval Queue Page
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-3 (Access Enforcement) - Role-based approval workflow
//! - NIAP PP-CA: FMT_MOF.1 (Management of Security Functions)

use std::rc::Rc;
use yew::prelude::*;

use crate::components::auth::Protected;
use crate::components::common::{
    Alert, AlertType, Badge, BadgeVariant, Column, DataTable, Loading, Modal,
};

/// Approval request status
#[derive(Clone, PartialEq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

impl ApprovalStatus {
    fn as_str(&self) -> &'static str {
        match self {
            ApprovalStatus::Pending => "Pending",
            ApprovalStatus::Approved => "Approved",
            ApprovalStatus::Denied => "Denied",
            ApprovalStatus::Expired => "Expired",
        }
    }

    fn badge_variant(&self) -> BadgeVariant {
        match self {
            ApprovalStatus::Pending => BadgeVariant::Warning,
            ApprovalStatus::Approved => BadgeVariant::Success,
            ApprovalStatus::Denied => BadgeVariant::Danger,
            ApprovalStatus::Expired => BadgeVariant::Default,
        }
    }
}

/// Approval request type
#[derive(Clone, PartialEq)]
pub enum RequestType {
    CertificateIssuance,
    CertificateRevocation,
    KeyRecovery,
    RoleChange,
}

impl RequestType {
    fn as_str(&self) -> &'static str {
        match self {
            RequestType::CertificateIssuance => "Certificate Issuance",
            RequestType::CertificateRevocation => "Certificate Revocation",
            RequestType::KeyRecovery => "Key Recovery",
            RequestType::RoleChange => "Role Change",
        }
    }
}

/// Approval request data
#[derive(Clone, PartialEq)]
pub struct ApprovalRequest {
    pub id: String,
    pub request_type: RequestType,
    pub subject: String,
    pub requestor: String,
    pub requestor_email: String,
    pub created_at: String,
    pub expires_at: String,
    pub status: ApprovalStatus,
    pub details: String,
    pub priority: String,
}

/// Approvals page state
struct ApprovalsState {
    requests: Vec<ApprovalRequest>,
    loading: bool,
    error: Option<String>,
    selected_request: Option<ApprovalRequest>,
    show_approve_modal: bool,
    show_deny_modal: bool,
    filter_status: String,
    filter_type: String,
    current_page: usize,
}

/// Approvals page
#[function_component(Approvals)]
pub fn approvals() -> Html {
    let state = use_state(|| ApprovalsState {
        requests: get_sample_requests(),
        loading: false,
        error: None,
        selected_request: None,
        show_approve_modal: false,
        show_deny_modal: false,
        filter_status: "pending".to_string(),
        filter_type: "all".to_string(),
        current_page: 1,
    });

    let on_approve_click = {
        let state = state.clone();
        Callback::from(move |request: ApprovalRequest| {
            let mut new_state = (*state).clone();
            new_state.selected_request = Some(request);
            new_state.show_approve_modal = true;
            state.set(new_state);
        })
    };

    let on_deny_click = {
        let state = state.clone();
        Callback::from(move |request: ApprovalRequest| {
            let mut new_state = (*state).clone();
            new_state.selected_request = Some(request);
            new_state.show_deny_modal = true;
            state.set(new_state);
        })
    };

    let on_close_modal = {
        let state = state.clone();
        Callback::from(move |_| {
            let mut new_state = (*state).clone();
            new_state.show_approve_modal = false;
            new_state.show_deny_modal = false;
            new_state.selected_request = None;
            state.set(new_state);
        })
    };

    let on_confirm_approve = {
        let state = state.clone();
        Callback::from(move |_| {
            // In real implementation, this would call the API
            let mut new_state = (*state).clone();
            if let Some(ref request) = new_state.selected_request {
                new_state.requests.retain(|r| r.id != request.id);
            }
            new_state.show_approve_modal = false;
            new_state.selected_request = None;
            state.set(new_state);
        })
    };

    let on_confirm_deny = {
        let state = state.clone();
        Callback::from(move |_| {
            // In real implementation, this would call the API
            let mut new_state = (*state).clone();
            if let Some(ref request) = new_state.selected_request {
                new_state.requests.retain(|r| r.id != request.id);
            }
            new_state.show_deny_modal = false;
            new_state.selected_request = None;
            state.set(new_state);
        })
    };

    let on_status_filter_change = {
        let state = state.clone();
        Callback::from(move |e: Event| {
            let target = e.target_unchecked_into::<web_sys::HtmlSelectElement>();
            let mut new_state = (*state).clone();
            new_state.filter_status = target.value();
            new_state.current_page = 1;
            state.set(new_state);
        })
    };

    let on_type_filter_change = {
        let state = state.clone();
        Callback::from(move |e: Event| {
            let target = e.target_unchecked_into::<web_sys::HtmlSelectElement>();
            let mut new_state = (*state).clone();
            new_state.filter_type = target.value();
            new_state.current_page = 1;
            state.set(new_state);
        })
    };

    let on_page_change = {
        let state = state.clone();
        Callback::from(move |page: usize| {
            let mut new_state = (*state).clone();
            new_state.current_page = page;
            state.set(new_state);
        })
    };

    // Filter requests
    let filtered_requests: Vec<_> = state
        .requests
        .iter()
        .filter(|r| {
            let status_match = match state.filter_status.as_str() {
                "all" => true,
                "pending" => matches!(r.status, ApprovalStatus::Pending),
                "approved" => matches!(r.status, ApprovalStatus::Approved),
                "denied" => matches!(r.status, ApprovalStatus::Denied),
                _ => true,
            };
            let type_match = match state.filter_type.as_str() {
                "all" => true,
                "certificate" => matches!(
                    r.request_type,
                    RequestType::CertificateIssuance | RequestType::CertificateRevocation
                ),
                "key_recovery" => matches!(r.request_type, RequestType::KeyRecovery),
                "role_change" => matches!(r.request_type, RequestType::RoleChange),
                _ => true,
            };
            status_match && type_match
        })
        .cloned()
        .collect();

    // Count pending for badge
    let pending_count = state
        .requests
        .iter()
        .filter(|r| matches!(r.status, ApprovalStatus::Pending))
        .count();

    // Build columns
    let on_approve = on_approve_click.clone();
    let on_deny = on_deny_click.clone();

    let columns: Vec<Column<ApprovalRequest>> = vec![
        Column {
            label: "Request Type".to_string(),
            key: "type".to_string(),
            sortable: true,
            render: Rc::new(|req: &ApprovalRequest| {
                html! {
                    <span class="font-medium text-gray-900">
                        {req.request_type.as_str()}
                    </span>
                }
            }),
        },
        Column {
            label: "Subject".to_string(),
            key: "subject".to_string(),
            sortable: true,
            render: Rc::new(|req: &ApprovalRequest| {
                html! {
                    <div>
                        <div class="font-medium text-gray-900">{&req.subject}</div>
                        <div class="text-xs text-gray-500">{&req.details}</div>
                    </div>
                }
            }),
        },
        Column {
            label: "Requestor".to_string(),
            key: "requestor".to_string(),
            sortable: true,
            render: Rc::new(|req: &ApprovalRequest| {
                html! {
                    <div>
                        <div class="text-gray-900">{&req.requestor}</div>
                        <div class="text-xs text-gray-500">{&req.requestor_email}</div>
                    </div>
                }
            }),
        },
        Column {
            label: "Created".to_string(),
            key: "created_at".to_string(),
            sortable: true,
            render: Rc::new(|req: &ApprovalRequest| {
                html! { <span>{&req.created_at}</span> }
            }),
        },
        Column {
            label: "Expires".to_string(),
            key: "expires_at".to_string(),
            sortable: true,
            render: Rc::new(|req: &ApprovalRequest| {
                html! { <span>{&req.expires_at}</span> }
            }),
        },
        Column {
            label: "Priority".to_string(),
            key: "priority".to_string(),
            sortable: true,
            render: Rc::new(|req: &ApprovalRequest| {
                let variant = match req.priority.as_str() {
                    "High" => BadgeVariant::Danger,
                    "Medium" => BadgeVariant::Warning,
                    _ => BadgeVariant::Default,
                };
                html! { <Badge text={req.priority.clone()} variant={variant} /> }
            }),
        },
        Column {
            label: "Status".to_string(),
            key: "status".to_string(),
            sortable: true,
            render: Rc::new(|req: &ApprovalRequest| {
                html! {
                    <Badge
                        text={req.status.as_str().to_string()}
                        variant={req.status.badge_variant()}
                        dot={true}
                    />
                }
            }),
        },
        Column {
            label: "Actions".to_string(),
            key: "actions".to_string(),
            sortable: false,
            render: {
                let on_approve = on_approve.clone();
                let on_deny = on_deny.clone();
                Rc::new(move |req: &ApprovalRequest| {
                    if matches!(req.status, ApprovalStatus::Pending) {
                        let req_approve = req.clone();
                        let req_deny = req.clone();
                        let on_approve = on_approve.clone();
                        let on_deny = on_deny.clone();
                        html! {
                            <div class="flex gap-2">
                                <button
                                    type="button"
                                    class="btn btn-sm btn-success"
                                    onclick={Callback::from(move |e: MouseEvent| {
                                        e.stop_propagation();
                                        on_approve.emit(req_approve.clone());
                                    })}
                                >
                                    {"Approve"}
                                </button>
                                <button
                                    type="button"
                                    class="btn btn-sm btn-danger"
                                    onclick={Callback::from(move |e: MouseEvent| {
                                        e.stop_propagation();
                                        on_deny.emit(req_deny.clone());
                                    })}
                                >
                                    {"Deny"}
                                </button>
                            </div>
                        }
                    } else {
                        html! {
                            <span class="text-gray-400 text-sm">{"—"}</span>
                        }
                    }
                })
            },
        },
    ];

    html! {
        <Protected permission="view_approvals">
            <div class="page-header">
                <div class="flex items-center gap-3">
                    <h1 class="page-title">{"Approval Queue"}</h1>
                    if pending_count > 0 {
                        <Badge
                            text={pending_count.to_string()}
                            variant={BadgeVariant::Warning}
                        />
                    }
                </div>
                <p class="page-description">{"Review and approve certificate requests"}</p>
            </div>

            // Error alert
            if let Some(error) = &state.error {
                <div class="mb-4">
                    <Alert
                        message={error.clone()}
                        alert_type={AlertType::Error}
                        dismissible={true}
                    />
                </div>
            }

            // Filters
            <div class="card mb-4">
                <div class="card-body">
                    <div class="flex flex-wrap gap-4 items-end">
                        <div class="flex-1 min-w-[200px]">
                            <label class="form-label">
                                {"Status"}
                            </label>
                            <select
                                class="form-select"
                                value={state.filter_status.clone()}
                                onchange={on_status_filter_change}
                            >
                                <option value="pending">{"Pending"}</option>
                                <option value="all">{"All"}</option>
                                <option value="approved">{"Approved"}</option>
                                <option value="denied">{"Denied"}</option>
                            </select>
                        </div>
                        <div class="flex-1 min-w-[200px]">
                            <label class="form-label">
                                {"Request Type"}
                            </label>
                            <select
                                class="form-select"
                                value={state.filter_type.clone()}
                                onchange={on_type_filter_change}
                            >
                                <option value="all">{"All Types"}</option>
                                <option value="certificate">{"Certificate"}</option>
                                <option value="key_recovery">{"Key Recovery"}</option>
                                <option value="role_change">{"Role Change"}</option>
                            </select>
                        </div>
                        <div class="flex gap-2">
                            <button type="button" class="btn btn-secondary">
                                <svg class="h-4 w-4 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                                </svg>
                                {"Refresh"}
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            // Main content
            if state.loading {
                <Loading message={Some("Loading approval queue...".to_string())} />
            } else {
                <DataTable<ApprovalRequest>
                    data={filtered_requests.clone()}
                    columns={columns}
                    loading={state.loading}
                    empty_message={"No approval requests found".to_string()}
                    current_page={state.current_page}
                    total_items={filtered_requests.len()}
                    page_size={10}
                    on_page_change={Some(on_page_change)}
                />
            }

            // Approve Modal
            if state.show_approve_modal {
                if let Some(request) = &state.selected_request {
                    <Modal
                        open={true}
                        title={"Approve Request".to_string()}
                        on_close={on_close_modal.clone()}
                        footer={Some(html! {
                            <>
                                <button
                                    type="button"
                                    class="btn btn-secondary"
                                    onclick={on_close_modal.reform(|_: MouseEvent| ())}
                                >
                                    {"Cancel"}
                                </button>
                                <button
                                    type="button"
                                    class="btn btn-success"
                                    onclick={on_confirm_approve}
                                >
                                    {"Approve Request"}
                                </button>
                            </>
                        })}
                    >
                        <div class="space-y-4">
                            <Alert
                                alert_type={AlertType::Info}
                                message={"This action will approve the request and trigger the requested operation.".to_string()}
                            />
                            <dl class="grid grid-cols-2 gap-4">
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Request Type"}</dt>
                                    <dd class="text-sm text-gray-900">{request.request_type.as_str()}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Subject"}</dt>
                                    <dd class="text-sm text-gray-900">{&request.subject}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Requestor"}</dt>
                                    <dd class="text-sm text-gray-900">{&request.requestor}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Created"}</dt>
                                    <dd class="text-sm text-gray-900">{&request.created_at}</dd>
                                </div>
                            </dl>
                            <div>
                                <label class="form-label">
                                    {"Approval Notes (Optional)"}
                                </label>
                                <textarea
                                    class="form-textarea w-full"
                                    rows="3"
                                    placeholder="Add any notes about this approval..."
                                />
                            </div>
                        </div>
                    </Modal>
                }
            }

            // Deny Modal
            if state.show_deny_modal {
                if let Some(request) = &state.selected_request {
                    <Modal
                        open={true}
                        title={"Deny Request".to_string()}
                        on_close={on_close_modal.clone()}
                        footer={Some(html! {
                            <>
                                <button
                                    type="button"
                                    class="btn btn-secondary"
                                    onclick={on_close_modal.reform(|_: MouseEvent| ())}
                                >
                                    {"Cancel"}
                                </button>
                                <button
                                    type="button"
                                    class="btn btn-danger"
                                    onclick={on_confirm_deny}
                                >
                                    {"Deny Request"}
                                </button>
                            </>
                        })}
                    >
                        <div class="space-y-4">
                            <Alert
                                alert_type={AlertType::Warning}
                                message={"This action will deny the request. The requestor will be notified.".to_string()}
                            />
                            <dl class="grid grid-cols-2 gap-4">
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Request Type"}</dt>
                                    <dd class="text-sm text-gray-900">{request.request_type.as_str()}</dd>
                                </div>
                                <div>
                                    <dt class="text-sm font-medium text-gray-500">{"Subject"}</dt>
                                    <dd class="text-sm text-gray-900">{&request.subject}</dd>
                                </div>
                            </dl>
                            <div>
                                <label class="form-label">
                                    {"Denial Reason"}
                                    <span class="text-red-500 ml-1">{"*"}</span>
                                </label>
                                <textarea
                                    class="form-textarea w-full"
                                    rows="3"
                                    placeholder="Provide a reason for denying this request..."
                                    required={true}
                                />
                            </div>
                        </div>
                    </Modal>
                }
            }
        </Protected>
    }
}

impl Clone for ApprovalsState {
    fn clone(&self) -> Self {
        Self {
            requests: self.requests.clone(),
            loading: self.loading,
            error: self.error.clone(),
            selected_request: self.selected_request.clone(),
            show_approve_modal: self.show_approve_modal,
            show_deny_modal: self.show_deny_modal,
            filter_status: self.filter_status.clone(),
            filter_type: self.filter_type.clone(),
            current_page: self.current_page,
        }
    }
}

/// Generate sample approval requests for demo purposes
fn get_sample_requests() -> Vec<ApprovalRequest> {
    vec![
        ApprovalRequest {
            id: "REQ-001".to_string(),
            request_type: RequestType::CertificateIssuance,
            subject: "CN=api.example.com".to_string(),
            requestor: "John Smith".to_string(),
            requestor_email: "john.smith@example.com".to_string(),
            created_at: "2025-01-07 09:15".to_string(),
            expires_at: "2025-01-14 09:15".to_string(),
            status: ApprovalStatus::Pending,
            details: "TLS Server Certificate - 2 year validity".to_string(),
            priority: "High".to_string(),
        },
        ApprovalRequest {
            id: "REQ-002".to_string(),
            request_type: RequestType::CertificateRevocation,
            subject: "CN=old-server.example.com".to_string(),
            requestor: "Jane Doe".to_string(),
            requestor_email: "jane.doe@example.com".to_string(),
            created_at: "2025-01-07 08:30".to_string(),
            expires_at: "2025-01-14 08:30".to_string(),
            status: ApprovalStatus::Pending,
            details: "Reason: Key Compromise".to_string(),
            priority: "High".to_string(),
        },
        ApprovalRequest {
            id: "REQ-003".to_string(),
            request_type: RequestType::KeyRecovery,
            subject: "user@example.com encryption key".to_string(),
            requestor: "Bob Wilson".to_string(),
            requestor_email: "bob.wilson@example.com".to_string(),
            created_at: "2025-01-06 14:22".to_string(),
            expires_at: "2025-01-13 14:22".to_string(),
            status: ApprovalStatus::Pending,
            details: "Employee laptop replacement".to_string(),
            priority: "Medium".to_string(),
        },
        ApprovalRequest {
            id: "REQ-004".to_string(),
            request_type: RequestType::CertificateIssuance,
            subject: "CN=mail.example.com".to_string(),
            requestor: "Alice Brown".to_string(),
            requestor_email: "alice.brown@example.com".to_string(),
            created_at: "2025-01-06 11:00".to_string(),
            expires_at: "2025-01-13 11:00".to_string(),
            status: ApprovalStatus::Pending,
            details: "Email Server Certificate".to_string(),
            priority: "Low".to_string(),
        },
        ApprovalRequest {
            id: "REQ-005".to_string(),
            request_type: RequestType::RoleChange,
            subject: "charlie@example.com".to_string(),
            requestor: "HR System".to_string(),
            requestor_email: "hr-system@example.com".to_string(),
            created_at: "2025-01-05 16:45".to_string(),
            expires_at: "2025-01-12 16:45".to_string(),
            status: ApprovalStatus::Pending,
            details: "Promotion to CA Operator role".to_string(),
            priority: "Medium".to_string(),
        },
    ]
}
