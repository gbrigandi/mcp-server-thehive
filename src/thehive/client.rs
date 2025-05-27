use reqwest::Client;
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use thehive_client::{
    apis::{alert_api, case_api, configuration::Configuration, query_api},
    models::{
        FindEntitiesByQuery200Response, InputCase, InputQuery, OutputAlert, OutputCase,
        QueryOperation,
    },
};
use tracing::{debug, error, info};

use super::error::TheHiveApiError;

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

    pub async fn get_alerts(
        &self,
        limit: Option<u32>,
    ) -> Result<Vec<OutputAlert>, TheHiveApiError> {
        let current_limit = limit.unwrap_or(100);
        debug!(limit = current_limit, "Retrieving alerts from TheHive");

        // Create page operation with limit
        let mut page_op_fields = HashMap::new();
        page_op_fields.insert("from".to_string(), json!(0));
        page_op_fields.insert("to".to_string(), json!(current_limit));
        page_op_fields.insert("extraData".to_string(), json!([])); // Consistent with get_cases

        let page_op = QueryOperation {
            _name: Some("page".to_string()),
            additional_fields: page_op_fields,
        };

        // Assuming name="listAlert" is specific, query body might only need page_op.
        // If this doesn't work, a "listAlert" QueryOperation might also be needed in the vector.
        let query_payload = InputQuery {
            query: Some(vec![page_op]),
            exclude_fields: None,
        };

        info!(
            "Executing query to retrieve up to {} alerts from TheHive",
            current_limit
        );

        match query_api::find_entities_by_query(
            &self.configuration,
            query_payload,
            None,
            Some("listAlert"),
        )
        .await
        {
            Ok(response) => match response {
                FindEntitiesByQuery200Response::Array(alerts_json) => {
                    debug!(
                        "Successfully retrieved {} alerts from TheHive",
                        alerts_json.len()
                    );
                    let mut alerts = Vec::new();
                    for alert_value in alerts_json {
                        match serde_json::from_value::<OutputAlert>(alert_value.clone()) {
                            Ok(alert) => {
                                alerts.push(alert);
                            }
                            Err(e) => {
                                error!(
                                    "Error deserializing alert: {}. Raw JSON: {}",
                                    e, alert_value
                                );
                                return Err(TheHiveApiError::ClientError(format!(
                                    "Failed to deserialize alert: {}",
                                    e
                                )));
                            }
                        }
                    }
                    Ok(alerts)
                }
                _ => Err(TheHiveApiError::ClientError(
                    "Unexpected response format when fetching alerts".to_string(),
                )),
            },
            Err(e) => {
                error!("Failed to retrieve alerts from TheHive: {}", e);
                Err(TheHiveApiError::from(e))
            }
        }
    }

    pub async fn create_case(
        &self,
        case_payload: InputCase,
    ) -> Result<OutputCase, TheHiveApiError> {
        debug!(title = %case_payload.title, "Creating case in TheHive");
        info!("Creating case titled: {}", case_payload.title);

        match case_api::create_case(&self.configuration, case_payload, None).await {
            Ok(case) => {
                debug!("Successfully created case with ID: {}", case._id);
                Ok(case)
            }
            Err(e) => {
                error!("Failed to create case in TheHive: {}", e);
                Err(TheHiveApiError::from(e))
            }
        }
    }

    pub async fn get_alert_by_id(&self, alert_id: &str) -> Result<OutputAlert, TheHiveApiError> {
        debug!(alert_id, "Retrieving alert by ID from TheHive");
        info!("Fetching alert with ID: {}", alert_id);

        match alert_api::get_alert_by_id(&self.configuration, alert_id, None).await {
            Ok(alert) => {
                debug!("Successfully retrieved alert {} from TheHive", alert_id);
                Ok(alert)
            }
            Err(e) => {
                error!("Failed to retrieve alert {} from TheHive: {}", alert_id, e);
                Err(TheHiveApiError::from(e))
            }
        }
    }

    pub async fn get_cases(&self, limit: Option<u32>) -> Result<Vec<OutputCase>, TheHiveApiError> {
        let limit = limit.unwrap_or(100);
        debug!(limit, "Retrieving cases from TheHive");

        // Create listCase operation
        let list_case_op = QueryOperation {
            _name: Some("listCase".to_string()),
            additional_fields: HashMap::new(),
        };

        // Create page operation with limit
        let mut page_op_fields = HashMap::new();
        page_op_fields.insert("from".to_string(), json!(0));
        page_op_fields.insert("to".to_string(), json!(limit));
        page_op_fields.insert("extraData".to_string(), json!([]));

        let page_op = QueryOperation {
            _name: Some("page".to_string()),
            additional_fields: page_op_fields,
        };

        let query = InputQuery {
            query: Some(vec![list_case_op, page_op]),
            exclude_fields: None,
        };

        info!(
            "Executing query to retrieve up to {} cases from TheHive",
            limit
        );

        match query_api::find_entities_by_query(&self.configuration, query, None, Some("cases"))
            .await
        {
            Ok(response) => match response {
                FindEntitiesByQuery200Response::Array(cases_json) => {
                    debug!(
                        "Successfully retrieved {} cases from TheHive",
                        cases_json.len()
                    );
                    let mut cases = Vec::new();

                    for case_value in cases_json {
                        match serde_json::from_value::<OutputCase>(case_value.clone()) {
                            Ok(case) => {
                                cases.push(case);
                            }
                            Err(e) => {
                                error!("Error deserializing case: {}. Raw JSON: {}", e, case_value);
                                return Err(TheHiveApiError::ClientError(format!(
                                    "Failed to deserialize case: {}",
                                    e
                                )));
                            }
                        }
                    }

                    Ok(cases)
                }
                _ => Err(TheHiveApiError::ClientError(
                    "Unexpected response format when fetching cases".to_string(),
                )),
            },
            Err(e) => {
                error!("Failed to retrieve cases from TheHive: {}", e);
                Err(TheHiveApiError::from(e))
            }
        }
    }

    pub async fn get_case_by_id(&self, case_id: &str) -> Result<OutputCase, TheHiveApiError> {
        debug!(case_id, "Retrieving case by ID from TheHive");
        info!("Fetching case with ID: {}", case_id);

        match case_api::get_case_by_id(&self.configuration, case_id, None).await {
            Ok(case) => {
                debug!("Successfully retrieved case {} from TheHive", case_id);
                Ok(case)
            }
            Err(e) => {
                error!("Failed to retrieve case {} from TheHive: {}", case_id, e);
                Err(TheHiveApiError::from(e))
            }
        }
    }

    pub async fn promote_alert_to_case(
        &self,
        alert_id: &str,
    ) -> Result<OutputCase, TheHiveApiError> {
        debug!(alert_id, "Promoting alert to case in TheHive");
        info!("Promoting alert {} to case", alert_id);

        match alert_api::promote_alert_to_case(&self.configuration, alert_id, None, None).await {
            Ok(case) => {
                debug!("Successfully promoted alert {} to case", alert_id);
                Ok(case)
            }
            Err(e) => {
                error!("Failed to promote alert {} to case: {}", alert_id, e);
                Err(TheHiveApiError::from(e))
            }
        }
    }
}
