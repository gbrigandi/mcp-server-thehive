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
mod thehive {
    pub mod client;
    pub mod error;
}

use thehive::client::{RawCaseInput, RawObservableInput, TheHiveClient};

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

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct CreateCaseObservableParams {
    #[schemars(description = "The ID of the case to add the observable to.")]
    case_id: String,
    #[schemars(description = "The type of observable (e.g., 'ip', 'domain', 'url', 'hash', 'mail', 'filename', 'fqdn', 'uri_path', 'user-agent', 'autonomous-system', 'other').")]
    data_type: String,
    #[schemars(description = "The value of the observable.")]
    data: String,
    #[schemars(description = "Optional message/description for the observable.")]
    message: Option<String>,
    #[schemars(description = "TLP (Traffic Light Protocol) level (0-4). Defaults to case TLP if not specified.")]
    tlp: Option<i32>,
    #[schemars(description = "PAP (Permissible Actions Protocol) level (0-3). Defaults to case PAP if not specified.")]
    pap: Option<i32>,
    #[schemars(description = "Whether this observable is an IOC (Indicator of Compromise). Defaults to false.")]
    ioc: Option<bool>,
    #[schemars(description = "Whether this observable has been sighted. Defaults to false.")]
    sighted: Option<bool>,
    #[schemars(description = "Tags to associate with the observable.")]
    tags: Option<Vec<String>>,
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
                        let id = &alert.id;
                        let title = &alert.title;
                        let severity = alert.severity;
                        let severity_label = &alert.severity_label;
                        let status = &alert.status;
                        let source = &alert.source;
                        let created_at = alert.created_at
                            .and_then(|ts| chrono::DateTime::from_timestamp(ts / 1000, 0))
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
                let id = &alert.id;
                let title = &alert.title;
                let description = &alert.description;
                let severity = alert.severity;
                let severity_label = &alert.severity_label;
                let status = &alert.status;
                let source = &alert.source;
                let source_ref = &alert.source_ref;
                let created_at = alert.created_at
                    .and_then(|ts| chrono::DateTime::from_timestamp(ts / 1000, 0))
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
                        let id = &case.id;
                        let number = case.number;
                        let title = &case.title;
                        let severity = case.severity;
                        let severity_label = &case.severity_label;
                        let status = &case.status;
                        let created_at = case.created_at
                            .and_then(|ts| chrono::DateTime::from_timestamp(ts / 1000, 0))
                            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                            .unwrap_or_else(|| "Unknown".to_string());
                        let assignee = case.assignee.as_deref().unwrap_or("Unassigned");

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
                let id = &case.id;
                let number = case.number;
                let title = &case.title;
                let description = &case.description;
                let severity = case.severity;
                let severity_label = &case.severity_label;
                let status = &case.status;
                let created_at = case.created_at
                    .and_then(|ts| chrono::DateTime::from_timestamp(ts / 1000, 0))
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "Unknown".to_string());
                let assignee = case.assignee.as_deref().unwrap_or("Unassigned");
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
                let case_id = &case.id;
                let case_number = case.number;
                let title = &case.title;
                let severity = case.severity;
                let severity_label = &case.severity_label;
                let status = &case.status;

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

        // Validate severity if provided (1-4)
        let severity = params.severity.map(|s| {
            if !(1..=4).contains(&s) {
                tracing::warn!("Invalid severity value {}, defaulting to Medium (2)", s);
                2
            } else {
                s
            }
        });

        // Validate TLP if provided (0-4)
        let tlp = params.tlp.map(|t| {
            if !(0..=4).contains(&t) {
                tracing::warn!("Invalid TLP value {}, defaulting to White (0)", t);
                0
            } else {
                t
            }
        });

        // Validate PAP if provided (0-3)
        let pap = params.pap.map(|p| {
            if !(0..=3).contains(&p) {
                tracing::warn!("Invalid PAP value {}, defaulting to White (0)", p);
                0
            } else {
                p
            }
        });

        // Build raw case input with proper JSON serialization
        let case_input = RawCaseInput {
            title: params.title,
            description: params.description,
            severity,
            tags: params.tags,
            tlp,
            pap,
            status: params.status,
            assignee: params.assignee,
            case_template: params.case_template,
            start_date: params.start_date,
        };

        match self.thehive_client.create_case_raw(case_input).await {
            Ok(case) => {
                let case_id = &case.id;
                let case_number = case.number;
                let title = &case.title;
                let severity = case.severity;
                let severity_label = &case.severity_label;
                let status = &case.status;

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

    #[tool(
        name = "create_case_observable",
        description = "Creates an observable on an existing TheHive case. Returns the newly created observable information."
    )]
    async fn create_case_observable(
        &self,
        #[tool(aggr)] params: CreateCaseObservableParams,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(case_id = %params.case_id, data_type = %params.data_type, "Creating observable on TheHive case");

        // Build observable input
        let observable_input = RawObservableInput {
            data_type: params.data_type,
            data: params.data,
            message: params.message,
            tlp: params.tlp,
            pap: params.pap,
            ioc: params.ioc,
            sighted: params.sighted,
            sighted_at: None,
            ignore_similarity: None,
            tags: params.tags,
        };

        match self
            .thehive_client
            .create_observable(&params.case_id, observable_input)
            .await
        {
            Ok(observable) => {
                let obs_id = &observable.id;
                let data_type = &observable.data_type;
                let data = observable.data.as_deref().unwrap_or("N/A");
                let ioc = if observable.ioc { "Yes" } else { "No" };
                let tlp_label = &observable.tlp_label;

                let formatted_text = format!(
                    "Successfully created observable.\nObservable ID: {}\nType: {}\nValue: {}\nIOC: {}\nTLP: {}",
                    obs_id, data_type, data, ioc, tlp_label
                );

                Ok(CallToolResult::success(vec![Content::text(formatted_text)]))
            }
            Err(e) => {
                let err_msg = format!(
                    "Error creating observable on case {}: {}",
                    params.case_id, e
                );
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
                Optional parameters include 'severity', 'tags', 'tlp', 'pap', 'status', 'assignee', 'case_template', and 'start_date'.\n\
                - 'create_case_observable': Creates an observable on an existing case. Requires 'case_id', 'data_type', and 'data'. \
                Optional parameters include 'message', 'tlp', 'pap', 'ioc', 'sighted', and 'tags'."
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
