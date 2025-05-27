//
// Purpose:
//
// This Rust application implements an MCP (Model Context Protocol) server that acts as a
// bridge to a TheHive instance. It exposes various TheHive functionalities as tools that can
// be invoked by MCP clients (e.g., AI models, automation scripts).
//
// Structure:
// - `main()`: Entry point of the application. Initializes logging (tracing),
//   sets up the `TheHiveToolsServer`, and starts the MCP server using stdio transport.
//
// - `TheHiveToolsServer`: The core struct that implements the `rmcp::ServerHandler` trait
//   and the `#[tool(tool_box)]` attribute.
//   - It holds the configuration for connecting to the TheHive API.
//   - Its methods, decorated with `#[tool(...)]`, define the actual tools available
//     to MCP clients (e.g., `get_thehive_alerts`, `get_thehive_cases`).
//
// - Tool Parameter Structs (e.g., `GetAlertsParams`, `GetCasesParams`):
//   - These structs define the expected input parameters for each tool.
//   - They use `serde::Deserialize` for parsing input and `schemars::JsonSchema`
//     for generating a schema that MCP clients can use to understand how to call the tools.
//
// - `thehive` module:
//   - `TheHiveClient`: Handles communication with the TheHive API.
//   - Provides methods to fetch alerts, cases, and other incident response data from TheHive.
//
// Workflow:
// 1. Server starts and listens for MCP requests on stdio.
// 2. MCP client sends a `call_tool` request.
// 3. `TheHiveToolsServer` dispatches to the appropriate tool method based on the tool name.
// 4. The tool method parses parameters, interacts with the TheHive client to fetch data.
// 5. The result (success with data or error) is packaged into a `CallToolResult`
//    and sent back to the MCP client.
//
// Configuration:
// The server requires `THEHIVE_URL` and `THEHIVE_API_TOKEN` environment variables
// to connect to the TheHive instance. Logging is controlled by `RUST_LOG`.

use clap::Parser;
use dotenv::dotenv;
use rmcp::{
    model::{
        CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
    },
    schemars, tool,
    transport::stdio,
    Error as McpError, ServerHandler, ServiceExt,
};
use std::env;
use std::sync::Arc;
use thehive_client::models::{
    input_case::{Pap as InputCasePap, Severity as InputCaseSeverity, Tlp as InputCaseTlp},
    CaseStatusValue, InputCase,
};

mod thehive {
    pub mod client;
    pub mod error;
}

use thehive::client::TheHiveClient;

#[derive(Parser, Debug)]
#[command(name = "mcp-server-thehive")]
#[command(about = "TheHive Incident Response Platform MCP Server")]
struct Args {
    // Currently only stdio transport is supported
    // Future versions may add HTTP-SSE transport
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GetAlertsParams {
    #[schemars(description = "Maximum number of alerts to retrieve (default: 100)")]
    limit: Option<u32>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GetAlertByIdParams {
    #[schemars(description = "The ID of the alert to retrieve")]
    alert_id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GetCasesParams {
    #[schemars(description = "Maximum number of cases to retrieve (default: 100)")]
    limit: Option<u32>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GetCaseByIdParams {
    #[schemars(description = "The ID of the case to retrieve")]
    case_id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct PromoteAlertToCaseParams {
    #[schemars(description = "The ID of the alert to promote to a case")]
    alert_id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct CreateCaseParams {
    #[schemars(description = "The title of the case.")]
    title: String,
    #[schemars(description = "The description of the case.")]
    description: String,
    #[schemars(
        description = "Severity of the case (e.g., 1 for Low, 2 for Medium, 3 for High, 4 for Critical). Defaults to Medium (2) if not specified."
    )]
    severity: Option<i32>,
    #[schemars(description = "Tags to associate with the case.")]
    tags: Option<Vec<String>>,
    #[schemars(
        description = "TLP (Traffic Light Protocol) level (e.g., 0 for White, 1 for Green, 2 for Amber, 3 for Red)."
    )]
    tlp: Option<i32>,
    #[schemars(
        description = "PAP (Permissible Actions Protocol) level (e.g., 0 for White, 1 for Green, 2 for Amber, 3 for Red)."
    )]
    pap: Option<i32>,
    #[schemars(
        description = "Status of the case (e.g., \"New\", \"Open\", \"InProgress\"). Defaults to \"New\" or template default."
    )]
    status: Option<String>,
    #[schemars(description = "Username of the assignee for the case.")]
    assignee: Option<String>,
    #[schemars(description = "Name or ID of the case template to use.")]
    case_template: Option<String>,
    #[schemars(description = "Start date of the case as a Unix timestamp in milliseconds.")]
    start_date: Option<i64>,
}

#[derive(Clone)]
struct TheHiveToolsServer {
    thehive_client: Arc<TheHiveClient>,
}

#[tool(tool_box)]
impl TheHiveToolsServer {
    fn new() -> Result<Self, anyhow::Error> {
        dotenv().ok();

        let thehive_url =
            env::var("THEHIVE_URL").unwrap_or_else(|_| "http://localhost:9000/api".to_string());

        let thehive_api_token = env::var("THEHIVE_API_TOKEN")
            .map_err(|_| anyhow::anyhow!("THEHIVE_API_TOKEN environment variable is required"))?;

        let verify_ssl = env::var("VERIFY_SSL")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase()
            == "true";

        tracing::debug!(
            ?thehive_url,
            ?verify_ssl,
            "Creating TheHive client with API token"
        );

        let thehive_client = TheHiveClient::new(thehive_url, thehive_api_token, verify_ssl)?;

        Ok(Self {
            thehive_client: Arc::new(thehive_client),
        })
    }

    #[tool(
        name = "get_thehive_alerts",
        description = "Retrieves a list of alerts from TheHive. Returns formatted alert information including ID, title, severity, and status."
    )]
    async fn get_thehive_alerts(
        &self,
        #[tool(aggr)] params: GetAlertsParams,
    ) -> Result<CallToolResult, McpError> {
        let limit = params.limit.unwrap_or(100);

        tracing::info!(limit = %limit, "Retrieving TheHive alerts");

        match self.thehive_client.get_alerts(Some(limit)).await {
            Ok(alerts) => {
                if alerts.is_empty() {
                    tracing::info!("No TheHive alerts found. Returning standard message.");
                    return Ok(CallToolResult::success(vec![Content::text(
                        "No TheHive alerts found.",
                    )]));
                }

                let mcp_content_items: Vec<Content> = alerts
                    .into_iter()
                    .map(|alert| {
                        let id = &alert._id;
                        let title = &alert.title;
                        let severity = alert.severity;
                        let severity_label = &alert.severity_label;
                        let status = &alert.status;
                        let source = &alert.source;
                        let created_at = chrono::DateTime::from_timestamp(alert._created_at, 0)
                            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                            .unwrap_or_else(|| "Unknown".to_string());

                        let formatted_text = format!(
                            "Alert ID: {}\nTitle: {}\nSeverity: {} ({})\nStatus: {}\nSource: {}\nCreated: {}",
                            id, title, severity, severity_label, status, source, created_at
                        );
                        Content::text(formatted_text)
                    })
                    .collect();

                tracing::info!(
                    "Successfully processed {} alerts into {} MCP content items",
                    mcp_content_items.len(),
                    mcp_content_items.len()
                );
                Ok(CallToolResult::success(mcp_content_items))
            }
            Err(e) => {
                let err_msg = format!("Error retrieving alerts from TheHive: {}", e);
                tracing::error!("{}", err_msg);
                Ok(CallToolResult::error(vec![Content::text(err_msg)]))
            }
        }
    }

    #[tool(
        name = "get_thehive_alert_by_id",
        description = "Retrieves a specific alert from TheHive by its ID. Returns detailed alert information."
    )]
    async fn get_thehive_alert_by_id(
        &self,
        #[tool(aggr)] params: GetAlertByIdParams,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(alert_id = %params.alert_id, "Retrieving TheHive alert by ID");

        match self.thehive_client.get_alert_by_id(&params.alert_id).await {
            Ok(alert) => {
                let id = &alert._id;
                let title = &alert.title;
                let description = &alert.description;
                let severity = alert.severity;
                let severity_label = &alert.severity_label;
                let status = &alert.status;
                let source = &alert.source;
                let source_ref = &alert.source_ref;
                let created_at = chrono::DateTime::from_timestamp(alert._created_at, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "Unknown".to_string());
                let tlp_label = &alert.tlp_label;
                let pap_label = &alert.pap_label;

                let formatted_text = format!(
                    "Alert ID: {}\nTitle: {}\nDescription: {}\nSeverity: {} ({})\nStatus: {}\nSource: {}\nSource Ref: {}\nTLP: {}\nPAP: {}\nCreated: {}",
                    id, title, description, severity, severity_label, status, source, source_ref, tlp_label, pap_label, created_at
                );

                Ok(CallToolResult::success(vec![Content::text(formatted_text)]))
            }
            Err(e) => {
                let err_msg = format!(
                    "Error retrieving alert {} from TheHive: {}",
                    params.alert_id, e
                );
                tracing::error!("{}", err_msg);
                Ok(CallToolResult::error(vec![Content::text(err_msg)]))
            }
        }
    }

    #[tool(
        name = "get_thehive_cases",
        description = "Retrieves a list of cases from TheHive. Returns formatted case information including ID, title, severity, and status."
    )]
    async fn get_thehive_cases(
        &self,
        #[tool(aggr)] params: GetCasesParams,
    ) -> Result<CallToolResult, McpError> {
        let limit = params.limit.unwrap_or(100);

        tracing::info!(limit = %limit, "Retrieving TheHive cases");

        match self.thehive_client.get_cases(Some(limit)).await {
            Ok(cases) => {
                if cases.is_empty() {
                    tracing::info!("No TheHive cases found. Returning standard message.");
                    return Ok(CallToolResult::success(vec![Content::text(
                        "No TheHive cases found.",
                    )]));
                }

                let mcp_content_items: Vec<Content> = cases
                    .into_iter()
                    .map(|case| {
                        let id = &case._id;
                        let number = case.number;
                        let title = &case.title;
                        let severity = case.severity;
                        let severity_label = &case.severity_label;
                        let status = format!("{:?}", case.status);
                        let created_at = chrono::DateTime::from_timestamp(case._created_at, 0)
                            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                            .unwrap_or_else(|| "Unknown".to_string());
                        let assignee = case.assignee.as_ref().and_then(|a| a.as_ref()).map(|s| s.as_str()).unwrap_or("Unassigned");

                        let formatted_text = format!(
                            "Case ID: {}\nCase Number: {}\nTitle: {}\nSeverity: {} ({})\nStatus: {}\nAssignee: {}\nCreated: {}",
                            id, number, title, severity, severity_label, status, assignee, created_at
                        );
                        Content::text(formatted_text)
                    })
                    .collect();

                tracing::info!(
                    "Successfully processed {} cases into {} MCP content items",
                    mcp_content_items.len(),
                    mcp_content_items.len()
                );
                Ok(CallToolResult::success(mcp_content_items))
            }
            Err(e) => {
                let err_msg = format!("Error retrieving cases from TheHive: {}", e);
                tracing::error!("{}", err_msg);
                Ok(CallToolResult::error(vec![Content::text(err_msg)]))
            }
        }
    }

    #[tool(
        name = "get_thehive_case_by_id",
        description = "Retrieves a specific case from TheHive by its ID. Returns detailed case information."
    )]
    async fn get_thehive_case_by_id(
        &self,
        #[tool(aggr)] params: GetCaseByIdParams,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(case_id = %params.case_id, "Retrieving TheHive case by ID");

        match self.thehive_client.get_case_by_id(&params.case_id).await {
            Ok(case) => {
                let id = &case._id;
                let number = case.number;
                let title = &case.title;
                let description = &case.description;
                let severity = case.severity;
                let severity_label = &case.severity_label;
                let status = format!("{:?}", case.status);
                let created_at = chrono::DateTime::from_timestamp(case._created_at, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "Unknown".to_string());
                let assignee = case
                    .assignee
                    .as_ref()
                    .and_then(|a| a.as_ref())
                    .map(|s| s.as_str())
                    .unwrap_or("Unassigned");
                let tlp_label = &case.tlp_label;
                let pap_label = &case.pap_label;

                let formatted_text = format!(
                    "Case ID: {}\nCase Number: {}\nTitle: {}\nDescription: {}\nSeverity: {} ({})\nStatus: {}\nAssignee: {}\nTLP: {}\nPAP: {}\nCreated: {}",
                    id, number, title, description, severity, severity_label, status, assignee, tlp_label, pap_label, created_at
                );

                Ok(CallToolResult::success(vec![Content::text(formatted_text)]))
            }
            Err(e) => {
                let err_msg = format!(
                    "Error retrieving case {} from TheHive: {}",
                    params.case_id, e
                );
                tracing::error!("{}", err_msg);
                Ok(CallToolResult::error(vec![Content::text(err_msg)]))
            }
        }
    }

    #[tool(
        name = "promote_alert_to_case",
        description = "Promotes a TheHive alert to a case. Returns the newly created case information."
    )]
    async fn promote_alert_to_case(
        &self,
        #[tool(aggr)] params: PromoteAlertToCaseParams,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(alert_id = %params.alert_id, "Promoting TheHive alert to case");

        match self
            .thehive_client
            .promote_alert_to_case(&params.alert_id)
            .await
        {
            Ok(case) => {
                let case_id = &case._id;
                let case_number = case.number;
                let title = &case.title;
                let severity = case.severity;
                let severity_label = &case.severity_label;
                let status = format!("{:?}", case.status);

                let formatted_text = format!(
                    "Successfully promoted alert {} to case.\nCase ID: {}\nCase Number: {}\nTitle: {}\nSeverity: {} ({})\nStatus: {}",
                    params.alert_id, case_id, case_number, title, severity, severity_label, status
                );

                Ok(CallToolResult::success(vec![Content::text(formatted_text)]))
            }
            Err(e) => {
                let err_msg = format!("Error promoting alert {} to case: {}", params.alert_id, e);
                tracing::error!("{}", err_msg);
                Ok(CallToolResult::error(vec![Content::text(err_msg)]))
            }
        }
    }

    #[tool(
        name = "create_thehive_case",
        description = "Creates a new case in TheHive. Returns the newly created case information."
    )]
    async fn create_thehive_case(
        &self,
        #[tool(aggr)] params: CreateCaseParams,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(title = %params.title, "Creating TheHive case");

        // Convert params to thehive_client::models::InputCase fields
        let severity_payload = params.severity.map(|s_val| {
            Some(match s_val {
                1 => InputCaseSeverity::Variant1,
                2 => InputCaseSeverity::Variant2,
                3 => InputCaseSeverity::Variant3,
                4 => InputCaseSeverity::Variant4,
                _ => {
                    tracing::warn!("Invalid severity value {}, defaulting to Medium (2)", s_val);
                    InputCaseSeverity::Variant2
                }
            })
        });

        let tlp_payload = params.tlp.map(|t_val| {
            Some(match t_val {
                0 => InputCaseTlp::Variant0,
                1 => InputCaseTlp::Variant1,
                2 => InputCaseTlp::Variant2,
                3 => InputCaseTlp::Variant3,
                4 => InputCaseTlp::Variant4,
                _ => {
                    tracing::warn!("Invalid TLP value {}, defaulting to White (0)", t_val);
                    InputCaseTlp::Variant0
                }
            })
        });

        let pap_payload = params.pap.map(|p_val| {
            Some(match p_val {
                0 => InputCasePap::Variant0,
                1 => InputCasePap::Variant1,
                2 => InputCasePap::Variant2,
                3 => InputCasePap::Variant3,
                _ => {
                    tracing::warn!("Invalid PAP value {}, defaulting to White (0)", p_val);
                    InputCasePap::Variant0
                }
            })
        });

        let status_payload = params.status.and_then(|s_val| {
            match s_val.as_str() {
                // Match against exact string values expected by TheHive
                "New" => Some(CaseStatusValue::New),
                "InProgress" => Some(CaseStatusValue::InProgress),
                "Indeterminate" => Some(CaseStatusValue::Indeterminate),
                "FalsePositive" => Some(CaseStatusValue::FalsePositive),
                "TruePositive" => Some(CaseStatusValue::TruePositive),
                "Other" => Some(CaseStatusValue::Other),
                "Duplicated" => Some(CaseStatusValue::Duplicated),
                _ => {
                    tracing::warn!("Invalid status string '{}', not setting status.", s_val);
                    None
                }
            }
        });

        let case_payload = InputCase {
            title: params.title,
            description: params.description,
            severity: severity_payload,
            tags: params.tags.map(Some),
            tlp: tlp_payload,
            pap: pap_payload,
            status: status_payload,
            assignee: params.assignee.map(Some),
            case_template: params.case_template.map(Some),
            start_date: params.start_date.map(Some),
            ..Default::default() // Initializes other fields (endDate, flag, customFields, etc.) to None/Default
        };

        match self.thehive_client.create_case(case_payload).await {
            Ok(case) => {
                // Assuming 'case' is a struct similar to the one returned by get_case_by_id
                let case_id = &case._id;
                let case_number = case.number;
                let title = &case.title;
                let severity = case.severity;
                let severity_label = &case.severity_label;
                let status = format!("{:?}", case.status); // Or case.status if it's already a string

                let formatted_text = format!(
                    "Successfully created case.\nCase ID: {}\nCase Number: {}\nTitle: {}\nSeverity: {} ({})\nStatus: {}",
                    case_id, case_number, title, severity, severity_label, status
                );

                Ok(CallToolResult::success(vec![Content::text(formatted_text)]))
            }
            Err(e) => {
                let err_msg = format!("Error creating case in TheHive: {}", e);
                tracing::error!("{}", err_msg);
                Ok(CallToolResult::error(vec![Content::text(err_msg)]))
            }
        }
    }
}

#[tool(tool_box)]
impl ServerHandler for TheHiveToolsServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_prompts()
                .enable_resources()
                .enable_tools()
                .build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "This server provides tools to interact with a TheHive incident response platform for security case management.\n\
                Available tools:\n\
                - 'get_thehive_alerts': Retrieves a list of alerts from TheHive. \
                Optionally takes 'limit' parameter to control the number of alerts returned (defaults to 100).\n\
                - 'get_thehive_alert_by_id': Retrieves a specific alert by its ID.\n\
                - 'get_thehive_cases': Retrieves a list of cases from TheHive. \
                Optionally takes 'limit' parameter to control the number of cases returned (defaults to 100).\n\
                - 'get_thehive_case_by_id': Retrieves a specific case by its ID.\n\
                - 'promote_alert_to_case': Promotes an alert to a case.\n\
                - 'create_thehive_case': Creates a new case in TheHive. Requires 'title' and 'description'. \
                Optional parameters include 'severity', 'tags', 'tlp', 'pap', 'status', 'assignee', 'case_template', and 'start_date'."
                    .to_string(),
            ),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::DEBUG.into()),
        )
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("Starting TheHive MCP Server...");

    // Create an instance of our TheHive tools server
    let server = TheHiveToolsServer::new().expect("Error initializing TheHive tools server");

    tracing::info!("Using stdio transport");
    let service = server.serve(stdio()).await.inspect_err(|e| {
        tracing::error!("serving error: {:?}", e);
    })?;

    service.waiting().await?;
    Ok(())
}
