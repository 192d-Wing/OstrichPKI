//! Authentication Service
//!
//! Provides authentication context and utilities for the Yew application.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AC-3 (Access Enforcement)
//! - NIST 800-53: IA-2 (Identification and Authentication)

use std::collections::HashMap;
use std::rc::Rc;
use yew::prelude::*;

/// User information
#[derive(Clone, Debug, PartialEq)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
}

/// Authentication state
#[derive(Clone, Debug, PartialEq)]
pub struct AuthState {
    pub is_authenticated: bool,
    pub user: Option<UserInfo>,
    pub session_locked: bool,
    /// True while the initial `/auth/userinfo` probe is in flight. Lets guards
    /// show a spinner instead of bouncing to login before the session (an
    /// httpOnly cookie the client can't read directly) has been verified.
    pub checking: bool,
}

impl Default for AuthState {
    fn default() -> Self {
        Self {
            is_authenticated: false,
            user: None,
            session_locked: false,
            checking: true,
        }
    }
}

/// Role to permissions mapping
fn role_permissions() -> HashMap<&'static str, Vec<&'static str>> {
    let mut map = HashMap::new();

    // Keys are the CA's role names (Role enum variants, as returned by
    // /auth/userinfo): Administrator, OperationsStaff, RaOfficer, Auditor, …
    let admin = vec![
        "view_certificates", "issue_certificates", "revoke_certificates",
        "view_approvals", "approve_requests",
        "read_audit_log",
        "view_tokens", "manage_tokens",
        "manage_users",
        "admin",
    ];
    map.insert("Administrator", admin.clone());
    map.insert("admin", admin); // legacy/alias

    let ops = vec![
        "view_certificates", "issue_certificates", "revoke_certificates",
        "view_approvals", "view_tokens", "manage_tokens",
    ];
    map.insert("OperationsStaff", ops);

    let ra = vec![
        "view_certificates", "issue_certificates",
        "view_approvals", "approve_requests",
    ];
    map.insert("RaOfficer", ra.clone());
    map.insert("ra_staff", ra); // legacy/alias

    let auditor = vec!["view_certificates", "read_audit_log"];
    map.insert("Auditor", auditor.clone());
    map.insert("auditor", auditor); // legacy/alias

    map.insert("user", vec!["view_certificates"]);

    map
}

/// Authentication context handle
#[derive(Clone, PartialEq)]
pub struct AuthContext {
    state: UseStateHandle<AuthState>,
}

impl AuthContext {
    /// Check if the user is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.state.is_authenticated
    }

    /// True while the initial session check is still running.
    pub fn is_checking(&self) -> bool {
        self.state.checking
    }

    /// Get the current user
    pub fn user(&self) -> Option<&UserInfo> {
        self.state.user.as_ref()
    }

    /// Check if the user has a specific permission
    pub fn has_permission(&self, permission: &str) -> bool {
        if let Some(user) = &self.state.user {
            let role_perms = role_permissions();
            for role in &user.roles {
                if let Some(perms) = role_perms.get(role.as_str()) {
                    if perms.contains(&permission) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if the user has a specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.state.user.as_ref()
            .map(|u| u.roles.iter().any(|r| r == role))
            .unwrap_or(false)
    }

    /// Log the user out
    pub fn logout(&self) {
        // Redirect to logout endpoint
        if let Some(window) = web_sys::window() {
            let _ = window.location().set_href("/auth/logout");
        }
    }

    /// Set the authentication state (called after login)
    pub fn set_authenticated(&self, user: UserInfo) {
        self.state.set(AuthState {
            is_authenticated: true,
            user: Some(user),
            session_locked: false,
            checking: false,
        });
    }
}

/// Context type for auth
pub type AuthContextHandle = Rc<AuthContext>;

/// Props for AuthProvider
#[derive(Properties, PartialEq)]
pub struct AuthProviderProps {
    pub children: Children,
}

/// Authentication provider component
#[function_component(AuthProvider)]
pub fn auth_provider(props: &AuthProviderProps) -> Html {
    let state = use_state(AuthState::default);

    // Check session on mount
    {
        let state = state.clone();
        use_effect_with((), move |_| {
            // Fetch user info from server
            wasm_bindgen_futures::spawn_local(async move {
                match fetch_user_info().await {
                    Ok(user) => {
                        state.set(AuthState {
                            is_authenticated: true,
                            user: Some(user),
                            session_locked: false,
                            checking: false,
                        });
                    }
                    Err(e) => {
                        tracing::debug!("Not authenticated: {}", e);
                        state.set(AuthState {
                            is_authenticated: false,
                            user: None,
                            session_locked: false,
                            checking: false,
                        });
                    }
                }
            });
            || ()
        });
    }

    let context = Rc::new(AuthContext { state });

    html! {
        <ContextProvider<AuthContextHandle> context={context}>
            { for props.children.iter() }
        </ContextProvider<AuthContextHandle>>
    }
}

/// Hook to access authentication context
#[hook]
pub fn use_auth() -> AuthContext {
    let context = use_context::<AuthContextHandle>()
        .expect("AuthProvider not found in component tree");
    (*context).clone()
}

/// Fetch user info from the server
async fn fetch_user_info() -> Result<UserInfo, String> {
    use gloo_net::http::Request;

    let response = Request::get("/auth/userinfo")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if response.status() != 200 {
        return Err("Not authenticated".to_string());
    }

    #[derive(serde::Deserialize)]
    struct UserInfoResponse {
        subject: String,
        username: Option<String>,
        email: Option<String>,
        roles: Vec<String>,
        session_locked: bool,
    }

    let data: UserInfoResponse = response
        .json()
        .await
        .map_err(|e| e.to_string())?;

    Ok(UserInfo {
        id: data.subject,
        username: data.username.unwrap_or_else(|| "User".to_string()),
        email: data.email,
        roles: data.roles,
    })
}
