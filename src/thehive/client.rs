use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use thehive_client::apis::configuration::Configuration;
use tracing::{debug, error, info};

use super::error::TheHiveApiError;

/// Raw case creation input that serializes correctly to TheHive API format
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawCaseInput {
    pub title: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tlp: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pap: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_date: Option<i64>,
}

/// Observable creation input for TheHive API
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawObservableInput {
    pub data_type: String,
    pub data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tlp: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pap: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ioc: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sighted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sighted_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_similarity: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// Observable response from TheHive API
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RawObservableOutput {
    #[serde(rename = "_id")]
    pub id: String,
    pub data_type: String,
    pub data: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub tlp: i32,
    #[serde(default)]
    pub tlp_label: String,
    #[serde(default)]
    pub pap: i32,
    #[serde(default)]
    pub pap_label: String,
    #[serde(default)]
    pub ioc: bool,
    #[serde(default)]
    pub sighted: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(rename = "_createdAt")]
    pub created_at: Option<i64>,
}

/// Raw case response that handles TheHive 5's actual status values (Open, Resolved, etc.)
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RawCaseOutput {
    #[serde(rename = "_id")]
    pub id: String,
    pub number: i32,
    pub title: String,
    pub description: String,
    pub severity: i32,
    #[serde(default)]
    pub severity_label: String,
    pub status: String,  // String to handle any status value
    #[serde(default)]
    pub tlp_label: String,
    #[serde(default)]
    pub pap_label: String,
    #[serde(rename = "_createdAt")]
    pub created_at: Option<i64>,
    #[serde(default)]
    pub assignee: Option<String>,
}

/// Raw alert response that handles TheHive 5 alert format
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RawAlertOutput {
    #[serde(rename = "_id")]
    pub id: String,
    #[serde(rename = "type")]
    pub alert_type: String,
    pub source: String,
    #[serde(default)]
    pub source_ref: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub severity: i32,
    #[serde(default)]
    pub severity_label: String,
    #[serde(rename = "_createdAt")]
    pub created_at: Option<i64>,
    pub date: Option<i64>,
    pub status: String,
    #[serde(default)]
    pub tlp: i32,
    #[serde(default)]
    pub tlp_label: String,
    #[serde(default)]
    pub pap: i32,
    #[serde(default)]
    pub pap_label: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub case_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TheHiveClient {
    configuration: Configuration,
}

impl TheHiveClient {
    pub fn new(
        base_url: String,
        api_token: String,
        verify_ssl: bool,
    ) -> Result<Self, TheHiveApiError> {
        debug!(%base_url, %verify_ssl, "Creating new TheHiveClient with API token");

        let client = Client::builder()
            .danger_accept_invalid_certs(!verify_ssl)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(TheHiveApiError::HttpClientCreationError)?;

        let configuration = Configuration {
            base_path: base_url,
            user_agent: Some("mcp-server-thehive/0.1.0".to_string()),
            client,
            basic_auth: None,
            oauth_access_token: None,
            bearer_access_token: Some(api_token),
            api_key: None,
        };

        debug!("TheHive client configuration created successfully with API token");

        Ok(Self { configuration })
    }

    /// Get alerts using TheHive 5 v1 API
    pub async fn get_alerts(
        &self,
        limit: Option<u32>,
    ) -> Result<Vec<RawAlertOutput>, TheHiveApiError> {
        let current_limit = limit.unwrap_or(100);
        debug!(limit = current_limit, "Retrieving alerts from TheHive");

        // TheHive 5 v1 API query format
        let query_payload = json!({
            "query": [
                { "_name": "listAlert" },
                { "_name": "page", "from": 0, "to": current_limit, "extraData": [] }
            ]
        });

        info!(
            "Executing query to retrieve up to {} alerts from TheHive (v1 API)",
            current_limit
        );

        let url = format!("{}/v1/query", self.configuration.base_path);

        let response = self.configuration.client
            .post(&url)
            .header("Content-Type", "application/json")
            .header(
                "Authorization",
                format!(
                    "Bearer {}",
                    self.configuration
                        .bearer_access_token
                        .as_ref()
                        .unwrap_or(&String::new())
                ),
            )
            .json(&query_payload)
            .send()
            .await
            .map_err(|e| TheHiveApiError::ClientError(format!("HTTP request failed: {}", e)))?;

        let status = response.status();
        let response_text = response.text().await.map_err(|e| {
            TheHiveApiError::ClientError(format!("Failed to read response body: {}", e))
        })?;

        if !status.is_success() {
            error!("TheHive API returned error: {} - {}", status, response_text);
            return Err(TheHiveApiError::ClientError(format!(
                "Get Alerts API error: {} - {}",
                status, response_text
            )));
        }

        // Parse the response as an array of alerts
        let alerts: Vec<RawAlertOutput> = serde_json::from_str(&response_text).map_err(|e| {
            error!("Failed to parse alerts response: {}. Raw: {}", e, response_text);
            TheHiveApiError::ClientError(format!("Failed to parse alerts response: {}", e))
        })?;

        debug!("Successfully retrieved {} alerts from TheHive", alerts.len());
        Ok(alerts)
    }

    /// Creates a case using raw JSON to bypass thehive-client enum serialization issues
    pub async fn create_case_raw(
        &self,
        case_input: RawCaseInput,
    ) -> Result<RawCaseOutput, TheHiveApiError> {
        debug!(title = %case_input.title, "Creating case in TheHive (raw JSON)");
        info!("Creating case titled: {}", case_input.title);

        // Log the JSON we're sending for debugging
        let json_body = serde_json::to_string(&case_input).map_err(|e| {
            TheHiveApiError::ClientError(format!("Failed to serialize case input: {}", e))
        })?;
        debug!("Case creation JSON payload: {}", json_body);

        // Build the URL for case creation (TheHive 5 v1 API)
        let url = format!("{}/v1/case", self.configuration.base_path);

        // Make the request directly using the configuration's client
        let response = self.configuration.client
            .post(&url)
            .header("Content-Type", "application/json")
            .header(
                "Authorization",
                format!(
                    "Bearer {}",
                    self.configuration
                        .bearer_access_token
                        .as_ref()
                        .unwrap_or(&String::new())
                ),
            )
            .json(&case_input)
            .send()
            .await
            .map_err(|e| TheHiveApiError::ClientError(format!("HTTP request failed: {}", e)))?;

        let status = response.status();
        let response_text = response.text().await.map_err(|e| {
            TheHiveApiError::ClientError(format!("Failed to read response body: {}", e))
        })?;

        if !status.is_success() {
            error!(
                "TheHive API returned error: {} - {}",
                status, response_text
            );
            return Err(TheHiveApiError::ClientError(format!(
                "Create Case API error: {} - {}",
                status, response_text
            )));
        }

        // Parse the response using our custom struct that handles TheHive 5 status values
        let case: RawCaseOutput = serde_json::from_str(&response_text).map_err(|e| {
            error!("Failed to parse case response: {}. Raw: {}", e, response_text);
            TheHiveApiError::ClientError(format!("Failed to parse case response: {}", e))
        })?;

        debug!("Successfully created case with ID: {}", case.id);
        info!("Case created successfully: {} ({})", case.title, case.id);
        Ok(case)
    }

    /// Get alert by ID using TheHive 5 v1 API
    pub async fn get_alert_by_id(&self, alert_id: &str) -> Result<RawAlertOutput, TheHiveApiError> {
        debug!(alert_id, "Retrieving alert by ID from TheHive");
        info!("Fetching alert with ID: {}", alert_id);

        let url = format!("{}/v1/alert/{}", self.configuration.base_path, alert_id);

        let response = self.configuration.client
            .get(&url)
            .header(
                "Authorization",
                format!(
                    "Bearer {}",
                    self.configuration
                        .bearer_access_token
                        .as_ref()
                        .unwrap_or(&String::new())
                ),
            )
            .send()
            .await
            .map_err(|e| TheHiveApiError::ClientError(format!("HTTP request failed: {}", e)))?;

        let status = response.status();
        let response_text = response.text().await.map_err(|e| {
            TheHiveApiError::ClientError(format!("Failed to read response body: {}", e))
        })?;

        if !status.is_success() {
            error!("TheHive API returned error: {} - {}", status, response_text);
            return Err(TheHiveApiError::ClientError(format!(
                "Get Alert API error: {} - {}",
                status, response_text
            )));
        }

        let alert: RawAlertOutput = serde_json::from_str(&response_text).map_err(|e| {
            error!("Failed to parse alert response: {}. Raw: {}", e, response_text);
            TheHiveApiError::ClientError(format!("Failed to parse alert response: {}", e))
        })?;

        debug!("Successfully retrieved alert {} from TheHive", alert_id);
        Ok(alert)
    }

    /// Get cases using TheHive 5 v1 API
    pub async fn get_cases(&self, limit: Option<u32>) -> Result<Vec<RawCaseOutput>, TheHiveApiError> {
        let current_limit = limit.unwrap_or(100);
        debug!(limit = current_limit, "Retrieving cases from TheHive");

        // TheHive 5 v1 API query format
        let query_payload = json!({
            "query": [
                { "_name": "listCase" },
                { "_name": "page", "from": 0, "to": current_limit, "extraData": [] }
            ]
        });

        info!(
            "Executing query to retrieve up to {} cases from TheHive (v1 API)",
            current_limit
        );

        let url = format!("{}/v1/query", self.configuration.base_path);

        let response = self.configuration.client
            .post(&url)
            .header("Content-Type", "application/json")
            .header(
                "Authorization",
                format!(
                    "Bearer {}",
                    self.configuration
                        .bearer_access_token
                        .as_ref()
                        .unwrap_or(&String::new())
                ),
            )
            .json(&query_payload)
            .send()
            .await
            .map_err(|e| TheHiveApiError::ClientError(format!("HTTP request failed: {}", e)))?;

        let status = response.status();
        let response_text = response.text().await.map_err(|e| {
            TheHiveApiError::ClientError(format!("Failed to read response body: {}", e))
        })?;

        if !status.is_success() {
            error!("TheHive API returned error: {} - {}", status, response_text);
            return Err(TheHiveApiError::ClientError(format!(
                "Get Cases API error: {} - {}",
                status, response_text
            )));
        }

        // Parse the response as an array of cases
        let cases: Vec<RawCaseOutput> = serde_json::from_str(&response_text).map_err(|e| {
            error!("Failed to parse cases response: {}. Raw: {}", e, response_text);
            TheHiveApiError::ClientError(format!("Failed to parse cases response: {}", e))
        })?;

        debug!("Successfully retrieved {} cases from TheHive", cases.len());
        Ok(cases)
    }

    /// Get case by ID using TheHive 5 v1 API
    pub async fn get_case_by_id(&self, case_id: &str) -> Result<RawCaseOutput, TheHiveApiError> {
        debug!(case_id, "Retrieving case by ID from TheHive");
        info!("Fetching case with ID: {}", case_id);

        let url = format!("{}/v1/case/{}", self.configuration.base_path, case_id);

        let response = self.configuration.client
            .get(&url)
            .header(
                "Authorization",
                format!(
                    "Bearer {}",
                    self.configuration
                        .bearer_access_token
                        .as_ref()
                        .unwrap_or(&String::new())
                ),
            )
            .send()
            .await
            .map_err(|e| TheHiveApiError::ClientError(format!("HTTP request failed: {}", e)))?;

        let status = response.status();
        let response_text = response.text().await.map_err(|e| {
            TheHiveApiError::ClientError(format!("Failed to read response body: {}", e))
        })?;

        if !status.is_success() {
            error!("TheHive API returned error: {} - {}", status, response_text);
            return Err(TheHiveApiError::ClientError(format!(
                "Get Case API error: {} - {}",
                status, response_text
            )));
        }

        let case: RawCaseOutput = serde_json::from_str(&response_text).map_err(|e| {
            error!("Failed to parse case response: {}. Raw: {}", e, response_text);
            TheHiveApiError::ClientError(format!("Failed to parse case response: {}", e))
        })?;

        debug!("Successfully retrieved case {} from TheHive", case_id);
        Ok(case)
    }

    /// Promote alert to case using TheHive 5 v1 API
    pub async fn promote_alert_to_case(
        &self,
        alert_id: &str,
    ) -> Result<RawCaseOutput, TheHiveApiError> {
        debug!(alert_id, "Promoting alert to case in TheHive");
        info!("Promoting alert {} to case", alert_id);

        // TheHive 5 v1 API endpoint: POST /api/v1/alert/{alertId}/case
        let url = format!("{}/v1/alert/{}/case", self.configuration.base_path, alert_id);

        let response = self.configuration.client
            .post(&url)
            .header("Content-Type", "application/json")
            .header(
                "Authorization",
                format!(
                    "Bearer {}",
                    self.configuration
                        .bearer_access_token
                        .as_ref()
                        .unwrap_or(&String::new())
                ),
            )
            .send()
            .await
            .map_err(|e| TheHiveApiError::ClientError(format!("HTTP request failed: {}", e)))?;

        let status = response.status();
        let response_text = response.text().await.map_err(|e| {
            TheHiveApiError::ClientError(format!("Failed to read response body: {}", e))
        })?;

        if !status.is_success() {
            error!("TheHive API returned error: {} - {}", status, response_text);
            return Err(TheHiveApiError::ClientError(format!(
                "Promote Alert to Case API error: {} - {}",
                status, response_text
            )));
        }

        let case: RawCaseOutput = serde_json::from_str(&response_text).map_err(|e| {
            error!("Failed to parse case response: {}. Raw: {}", e, response_text);
            TheHiveApiError::ClientError(format!("Failed to parse case response: {}", e))
        })?;

        debug!("Successfully promoted alert {} to case", alert_id);
        info!("Alert {} promoted to case: {}", alert_id, case.id);
        Ok(case)
    }

    /// Create observable on a case using TheHive 5 v1 API
    pub async fn create_observable(
        &self,
        case_id: &str,
        observable_input: RawObservableInput,
    ) -> Result<RawObservableOutput, TheHiveApiError> {
        debug!(case_id, data_type = %observable_input.data_type, "Creating observable on case in TheHive");
        info!("Creating observable ({}) on case {}", observable_input.data_type, case_id);

        // TheHive 5 v1 API endpoint: POST /api/v1/case/{caseId}/observable
        let url = format!("{}/v1/case/{}/observable", self.configuration.base_path, case_id);

        let response = self.configuration.client
            .post(&url)
            .header("Content-Type", "application/json")
            .header(
                "Authorization",
                format!(
                    "Bearer {}",
                    self.configuration
                        .bearer_access_token
                        .as_ref()
                        .unwrap_or(&String::new())
                ),
            )
            .json(&observable_input)
            .send()
            .await
            .map_err(|e| TheHiveApiError::ClientError(format!("HTTP request failed: {}", e)))?;

        let status = response.status();
        let response_text = response.text().await.map_err(|e| {
            TheHiveApiError::ClientError(format!("Failed to read response body: {}", e))
        })?;

        if !status.is_success() {
            error!("TheHive API returned error: {} - {}", status, response_text);
            return Err(TheHiveApiError::ClientError(format!(
                "Create Observable API error: {} - {}",
                status, response_text
            )));
        }

        // TheHive returns an array with a single observable
        let observables: Vec<RawObservableOutput> = serde_json::from_str(&response_text).map_err(|e| {
            error!("Failed to parse observable response: {}. Raw: {}", e, response_text);
            TheHiveApiError::ClientError(format!("Failed to parse observable response: {}", e))
        })?;

        let observable = observables.into_iter().next().ok_or_else(|| {
            TheHiveApiError::ClientError("Empty observable response from TheHive".to_string())
        })?;

        debug!("Successfully created observable {} on case {}", observable.id, case_id);
        info!("Observable created: {} ({})", observable.data_type, observable.id);
        Ok(observable)
    }
}
