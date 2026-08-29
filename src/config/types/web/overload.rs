use serde::{Deserialize, Serialize};

/// Action applied after an accepted WEB socket finds HTTP connection capacity exhausted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebHttpConnectionCapacityAction {
    /// Close the accepted socket without emitting an HTTP response.
    #[default]
    Drop,
    /// Wait for ordinary HTTP connection capacity under the overload deadline.
    Wait,
    /// Emit a bounded retryable HTTP response without parsing the request.
    Respond,
}
