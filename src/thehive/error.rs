use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum TheHiveApiError {
    #[error("Failed to create HTTP client: {0}")]
    HttpClientCreationError(reqwest::Error),

    #[error("HTTP request error: {0}")]
    RequestError(#[from] reqwest::Error),

    #[error("Authentication failed: {0}")]
    AuthenticationError(String),

    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("TheHive API error: {0}")]
    ApiError(String),

    #[error("Alert with ID '{0}' not found")]
    AlertNotFound(String),

    #[error("Case with ID '{0}' not found")]
    CaseNotFound(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("TheHive client error: {0}")]
    ClientError(String),
}

impl From<thehive_client::apis::Error<thehive_client::apis::alert_api::GetAlertByIdError>>
    for TheHiveApiError
{
    fn from(
        error: thehive_client::apis::Error<thehive_client::apis::alert_api::GetAlertByIdError>,
    ) -> Self {
        TheHiveApiError::ClientError(format!("Alert API error: {}", error))
    }
}

impl From<thehive_client::apis::Error<thehive_client::apis::case_api::GetCaseByIdError>>
    for TheHiveApiError
{
    fn from(
        error: thehive_client::apis::Error<thehive_client::apis::case_api::GetCaseByIdError>,
    ) -> Self {
        TheHiveApiError::ClientError(format!("Case API error: {}", error))
    }
}

impl From<thehive_client::apis::Error<thehive_client::apis::query_api::FindEntitiesByQueryError>>
    for TheHiveApiError
{
    fn from(
        error: thehive_client::apis::Error<
            thehive_client::apis::query_api::FindEntitiesByQueryError,
        >,
    ) -> Self {
        TheHiveApiError::ClientError(format!("Query API error: {}", error))
    }
}

impl From<thehive_client::apis::Error<thehive_client::apis::case_api::CreateCaseError>>
    for TheHiveApiError
{
    fn from(
        error: thehive_client::apis::Error<thehive_client::apis::case_api::CreateCaseError>,
    ) -> Self {
        TheHiveApiError::ClientError(format!("Create Case API error: {}", error))
    }
}

impl From<thehive_client::apis::Error<thehive_client::apis::alert_api::PromoteAlertToCaseError>>
    for TheHiveApiError
{
    fn from(
        error: thehive_client::apis::Error<
            thehive_client::apis::alert_api::PromoteAlertToCaseError,
        >,
    ) -> Self {
        TheHiveApiError::ClientError(format!("Promote Alert to Case API error: {}", error))
    }
}
