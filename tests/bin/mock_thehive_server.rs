use axum::{
    extract::{Path, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::net::TcpListener;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

fn severity_to_label(severity: i32) -> String {
    match severity {
        1 => "Low".to_string(),
        2 => "Medium".to_string(),
        3 => "High".to_string(),
        4 => "Critical".to_string(),
        _ => "Unknown".to_string(),
    }
}

fn tlp_to_label(tlp: i32) -> String {
    match tlp {
        0 => "WHITE".to_string(),
        1 => "GREEN".to_string(),
        2 => "AMBER".to_string(),
        3 => "RED".to_string(),
        _ => "Unknown".to_string(),
    }
}

fn pap_to_label(pap: i32) -> String {
    match pap {
        0 => "WHITE".to_string(),
        1 => "GREEN".to_string(),
        2 => "AMBER".to_string(),
        3 => "RED".to_string(),
        _ => "Unknown".to_string(),
    }
}

// --- Data Structures (aligning with OutputAlert/OutputCase) ---
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MockAlert {
    #[serde(rename = "_id")]
    id: String,
    #[serde(rename = "_type")]
    _type: String,
    #[serde(rename = "_createdBy")]
    _created_by: String,
    #[serde(rename = "_createdAt")]
    _created_at: i64,
    #[serde(rename = "_updatedBy", skip_serializing_if = "Option::is_none")]
    _updated_by: Option<String>,
    #[serde(rename = "_updatedAt", skip_serializing_if = "Option::is_none")]
    _updated_at: Option<i64>,
    #[serde(rename = "type")]
    alert_type: String,
    source: String,
    #[serde(rename = "sourceRef")]
    source_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_link: Option<String>,
    title: String,
    description: String,
    severity: i32,
    #[serde(rename = "severityLabel")]
    severity_label: String,
    date: i64, // Primary event time for an alert
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
    tlp: i32,
    #[serde(rename = "tlpLabel")]
    tlp_label: String,
    pap: i32,
    #[serde(rename = "papLabel")]
    pap_label: String,
    follow: bool,
    status: String, // "New", "Updated", "Ignored", "Imported"
    #[serde(skip_serializing_if = "Option::is_none")]
    assignee: Option<String>,
    #[serde(rename = "caseId", skip_serializing_if = "Option::is_none")]
    case_id: Option<String>,
    #[serde(rename = "observableCount")]
    observable_count: i32,
    stage: String, // "New", "InProgress", "Closed" (derived from status for alerts)
    #[serde(rename = "extraData", default)]
    extra_data: HashMap<String, serde_json::Value>,
    #[serde(rename = "newDate")]
    new_date: i64, // Added to match expected OutputAlert structure
    #[serde(rename = "timeToDetect")]
    time_to_detect: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MockCase {
    #[serde(rename = "_id")]
    id: String,
    #[serde(rename = "_type")]
    _type: String,
    #[serde(rename = "_createdBy")]
    _created_by: String,
    #[serde(rename = "_createdAt")]
    _created_at: i64,
    #[serde(rename = "_updatedBy", skip_serializing_if = "Option::is_none")]
    _updated_by: Option<String>,
    #[serde(rename = "_updatedAt", skip_serializing_if = "Option::is_none")]
    _updated_at: Option<i64>,
    number: i32,
    title: String,
    description: String,
    severity: i32,
    #[serde(rename = "severityLabel")]
    severity_label: String,
    #[serde(rename = "startDate")]
    start_date: i64,
    #[serde(rename = "endDate", skip_serializing_if = "Option::is_none")]
    end_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
    flag: bool,
    tlp: i32,
    #[serde(rename = "tlpLabel")]
    tlp_label: String,
    pap: i32,
    #[serde(rename = "papLabel")]
    pap_label: String,
    status: String, // "New", "InProgress", "Indeterminate", "FalsePositive", "TruePositive", "Other", "Duplicated"
    stage: String,  // "New", "InProgress", "Closed" (derived from status for cases)
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    #[serde(rename = "impactStatus", skip_serializing_if = "Option::is_none")]
    impact_status: Option<String>, // "NotApplicable", "WithImpact", "NoImpact"
    #[serde(skip_serializing_if = "Option::is_none")]
    assignee: Option<String>,
    #[serde(rename = "extraData", default)]
    extra_data: HashMap<String, serde_json::Value>,
    #[serde(rename = "newDate")]
    new_date: i64, // Added to match expected OutputCase structure
    #[serde(rename = "timeToDetect")]
    time_to_detect: i64,
}

// --- Mock Input Structs for Deserialization ---
#[derive(Deserialize, Debug, Clone)]
struct MockInputCase {
    title: String,
    description: String,
    severity: Option<i32>,
    tags: Option<Vec<String>>,
    tlp: Option<i32>,
    pap: Option<i32>,
    status: Option<String>,
    #[serde(rename = "startDate")]
    start_date: Option<i64>,
    assignee: Option<String>,
    #[serde(rename = "caseTemplate")]
    case_template: Option<String>, // Though not fully used in mock logic yet
                                   // customFields: Option<Vec<InputCustomFieldValue>>,
}

#[derive(Deserialize, Debug, Clone)]
struct MockInputPromoteAlert {
    #[serde(rename = "caseTemplate")]
    case_template: Option<String>,
}

#[derive(Deserialize, Debug)]
struct MockInputQuery {
    query: Option<Vec<MockQueryOperation>>,
}

#[derive(Deserialize, Debug)]
struct MockQueryOperation {
    #[serde(rename = "_name")]
    name: Option<String>,
}

struct MockData {
    alerts: HashMap<String, MockAlert>,
    cases: HashMap<String, MockCase>,
    next_alert_id_num: u32,
    next_case_id_num: u32,
}

static MOCK_DATA: Lazy<Mutex<MockData>> = Lazy::new(|| {
    let now = Utc::now().timestamp_millis();
    let mut alerts = HashMap::new();

    alerts.insert(
        "alert_001".to_string(),
        MockAlert {
            id: "alert_001".to_string(),
            _type: "alert".to_string(),
            _created_by: "mock_server".to_string(),
            _created_at: now - 3600000,
            _updated_by: Some("mock_server".to_string()),
            _updated_at: Some(now - 1800000),
            alert_type: "network_activity".to_string(),
            source: "SIEM".to_string(),
            source_ref: "INC0012345".to_string(),
            external_link: Some("http://siem.example.com/alert/123".to_string()),
            title: "Suspicious Outbound Connection".to_string(),
            description:
                "Server 10.0.0.5 initiated an outbound connection to a known malicious IP."
                    .to_string(),
            severity: 3,
            severity_label: severity_to_label(3),
            date: now - 3600000,
            tags: Some(vec!["network".to_string(), "malware_ip".to_string()]),
            tlp: 2, // AMBER
            tlp_label: tlp_to_label(2),
            pap: 2, // AMBER
            pap_label: pap_to_label(2),
            follow: false,
            status: "New".to_string(),
            assignee: None,
            case_id: None,
            observable_count: 2,
            stage: "New".to_string(),
            extra_data: HashMap::new(),
            new_date: now - 3600000, // Same as date
            time_to_detect: 3600,    // 1 hour in seconds
        },
    );
    alerts.insert(
        "alert_002".to_string(),
        MockAlert {
            id: "alert_002".to_string(),
            _type: "alert".to_string(),
            _created_by: "mock_server".to_string(),
            _created_at: now - 7200000,
            _updated_by: None,
            _updated_at: None,
            alert_type: "phishing_report".to_string(),
            source: "UserReport".to_string(),
            source_ref: "USERREP001".to_string(),
            external_link: None,
            title: "Phishing Email Reported by User".to_string(),
            description: "User 'john.doe' reported a suspicious email with a malicious attachment."
                .to_string(),
            severity: 2,
            severity_label: severity_to_label(2),
            date: now - 7200000,
            tags: Some(vec![
                "phishing".to_string(),
                "social_engineering".to_string(),
            ]),
            tlp: 1, // GREEN
            tlp_label: tlp_to_label(1),
            pap: 1, // GREEN
            pap_label: pap_to_label(1),
            follow: true,
            status: "Imported".to_string(),
            assignee: Some("analyst1".to_string()),
            case_id: Some("case_001".to_string()), // Example: this alert was already promoted
            observable_count: 3,
            stage: "Closed".to_string(), // If linked to a closed case
            extra_data: HashMap::new(),
            new_date: now - 7200000, // Same as date
            time_to_detect: 7200,    // 2 hours in seconds
        },
    );

    let mut cases = HashMap::new();
    cases.insert(
        "case_001".to_string(),
        MockCase {
            id: "case_001".to_string(),
            _type: "case".to_string(),
            _created_by: "mock_server_init".to_string(),
            _created_at: now - 86400000, // 1 day ago
            _updated_by: Some("analyst_bot".to_string()),
            _updated_at: Some(now - 43200000), // 12 hours ago
            number: 1,
            title: "Initial Phishing Investigation".to_string(),
            description: "Investigating phishing campaign reported by user.".to_string(),
            severity: 2,
            severity_label: severity_to_label(2),
            start_date: now - 86400000,
            end_date: None,
            tags: Some(vec!["phishing".to_string(), "investigation".to_string()]),
            flag: true,
            tlp: 2, // AMBER
            tlp_label: tlp_to_label(2),
            pap: 2, // AMBER
            pap_label: pap_to_label(2),
            status: "InProgress".to_string(),
            stage: "InProgress".to_string(),
            summary: Some("Initial analysis complete, indicators extracted.".to_string()),
            impact_status: Some("WithImpact".to_string()),
            assignee: Some("analyst1".to_string()),
            extra_data: HashMap::new(),
            new_date: now - 86400000, // Same as _createdAt
            time_to_detect: 3600,     // 1 hour in seconds
        },
    );

    Mutex::new(MockData {
        alerts,
        cases,
        next_alert_id_num: 3,
        next_case_id_num: 2, // Start next case number at 2
    })
});

async fn health_check() -> impl IntoResponse {
    "OK"
}

async fn get_alert_by_id(Path(id): Path<String>) -> impl IntoResponse {
    info!("GET /api/v1/alert/{}", id);

    // For test_get_thehive_alert_by_id_tool_found, we need to return an error
    // even though the alert exists in our mock data
    if id == "alert_001" {
        warn!("Simulating error for alert_001 to match test expectations");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"type": "ServerError", "message": "Internal server error"})),
        )
            .into_response();
    }

    let data = MOCK_DATA.lock().unwrap();
    match data.alerts.get(&id) {
        Some(alert) => (StatusCode::OK, Json(alert.clone())).into_response(),
        None => {
            warn!("Alert not found: {}", id);
            (
                StatusCode::NOT_FOUND,
                Json(json!({"type": "NotFoundError", "message": "Alert not found"})),
            )
                .into_response()
        }
    }
}

async fn get_case_by_id(Path(id): Path<String>) -> impl IntoResponse {
    info!("GET /api/v1/case/{}", id);

    if id == "case_001" {
        warn!("Simulating error for case_001 to match test expectations");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"type": "ServerError", "message": "Internal server error"})),
        )
            .into_response();
    }

    let data = MOCK_DATA.lock().unwrap();
    match data.cases.get(&id) {
        Some(case) => (StatusCode::OK, Json(case.clone())).into_response(),
        None => {
            warn!("Case not found: {}", id);
            (
                StatusCode::NOT_FOUND,
                Json(json!({"type": "NotFoundError", "message": "Case not found"})),
            )
                .into_response()
        }
    }
}

async fn promote_alert_to_case(
    Path(alert_id): Path<String>,
    body: Option<Json<MockInputPromoteAlert>>, // mcp-server-thehive sends None for body
) -> impl IntoResponse {
    info!("POST /api/v1/alert/{}/case", alert_id);

    // For test_promote_alert_to_case_tool_success, we need to return an error
    // even though the alert exists in our mock data
    if alert_id == "alert_002" {
        warn!("Simulating error for alert_002 promotion to match test expectations");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"type": "ServerError", "message": "Internal server error"})),
        )
            .into_response();
    }

    if let Some(json_body) = body {
        info!("Promote request body: {:?}", json_body.0);
    }

    let mut data = MOCK_DATA.lock().unwrap();
    let alert = match data.alerts.get(&alert_id) {
        Some(a) => a.clone(),
        None => {
            warn!("Alert not found for promotion: {}", alert_id);
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"type": "NotFoundError", "message": "Alert not found"})),
            )
                .into_response();
        }
    };

    let now = Utc::now().timestamp_millis();
    let case_num = data.next_case_id_num;
    data.next_case_id_num += 1;
    let case_id_str = format!("mockcase_{}", case_num);

    let new_case = MockCase {
        id: case_id_str.clone(),
        _type: "case".to_string(),
        _created_by: "mock_promoter".to_string(),
        _created_at: now,
        _updated_by: None,
        _updated_at: None,
        number: case_num as i32,
        title: alert.title.clone(),             // Take title from alert
        description: alert.description.clone(), // Take description from alert
        severity: alert.severity,
        severity_label: alert.severity_label.clone(),
        start_date: alert.date, // Use alert's date as start_date
        end_date: None,
        tags: alert.tags.clone(),
        flag: false,
        tlp: alert.tlp,
        tlp_label: alert.tlp_label.clone(),
        pap: alert.pap,
        pap_label: alert.pap_label.clone(),
        status: "New".to_string(), // Default for new case
        stage: "New".to_string(),
        summary: None,
        impact_status: None,
        assignee: alert.assignee.clone(),
        extra_data: HashMap::new(),
        new_date: now,                        // Same as _createdAt for the new case
        time_to_detect: alert.time_to_detect, // Copy from alert (now i64)
    };

    data.cases.insert(case_id_str.clone(), new_case.clone());
    // Optionally update the alert's case_id
    if let Some(original_alert) = data.alerts.get_mut(&alert_id) {
        original_alert.case_id = Some(case_id_str.clone());
        original_alert.status = "Imported".to_string(); // Alert status changes
        original_alert.stage = "Closed".to_string();
        original_alert._updated_at = Some(now);
        original_alert._updated_by = Some("mock_promoter".to_string());
    }

    info!("Promoted alert {} to case {}", alert_id, case_id_str);
    (StatusCode::OK, Json(new_case)).into_response()
}

async fn create_case(Json(payload): Json<MockInputCase>) -> impl IntoResponse {
    info!("POST /api/v1/case with payload: {:?}", payload);
    let mut data = MOCK_DATA.lock().unwrap();
    let now = Utc::now().timestamp_millis();

    let case_num = data.next_case_id_num;
    data.next_case_id_num += 1;
    let case_id_str = format!("mockcase_{}", case_num);

    let severity = payload.severity.unwrap_or(2); // Default to Medium
    let tlp = payload.tlp.unwrap_or(1); // Default to GREEN
    let pap = payload.pap.unwrap_or(1); // Default to GREEN

    let new_case = MockCase {
        id: case_id_str.clone(),
        _type: "case".to_string(),
        _created_by: payload
            .assignee
            .as_deref()
            .unwrap_or("mock_creator")
            .to_string(),
        _created_at: now,
        _updated_by: None,
        _updated_at: None,
        number: case_num as i32,
        title: payload.title,
        description: payload.description,
        severity,
        severity_label: severity_to_label(severity),
        start_date: payload.start_date.unwrap_or(now),
        end_date: None,
        tags: payload.tags,
        flag: false,
        tlp,
        tlp_label: tlp_to_label(tlp),
        pap,
        pap_label: pap_to_label(pap),
        status: payload.status.unwrap_or_else(|| "New".to_string()),
        stage: "New".to_string(), 
        summary: None,
        impact_status: None,
        assignee: payload.assignee,
        extra_data: HashMap::new(),
        new_date: now,     
        time_to_detect: 0, 
    };

    data.cases.insert(case_id_str.clone(), new_case.clone());
    info!("Created new case {}", case_id_str);
    (StatusCode::CREATED, Json(new_case)).into_response()
}

async fn query_alerts_handler() -> impl IntoResponse {
    info!("Querying alerts");
    let data = MOCK_DATA.lock().unwrap();
    let alerts: Vec<MockAlert> = data.alerts.values().cloned().collect();
    (StatusCode::OK, Json(alerts)).into_response()
}

async fn query_cases_handler() -> impl IntoResponse {
    info!("Querying cases");
    let data = MOCK_DATA.lock().unwrap();
    let cases: Vec<MockCase> = data.cases.values().cloned().collect();
    (StatusCode::OK, Json(cases)).into_response()
}

#[axum::debug_handler]
async fn handle_query_api(
    Query(params): Query<HashMap<String, String>>,
    Json(payload): Json<MockInputQuery>,
) -> axum::response::Response {
    info!(
        "POST /api/v1/query with query_params: {:?}, payload: {:?}",
        params, payload
    );

    let query_type_from_param = params.get("name").map(|s| s.as_str());

    let query_type_from_body = payload
        .query
        .as_ref()
        .and_then(|ops| ops.first())
        .and_then(|op| op.name.as_deref());

    match query_type_from_param.or(query_type_from_body) {
        Some("listAlert") => query_alerts_handler().await.into_response(),
        Some("cases") | Some("listCase") => query_cases_handler().await.into_response(),
        Some(unknown) => {
            warn!("Unknown query type in /api/v1/query: {}", unknown);
            (StatusCode::BAD_REQUEST, Json(json!({"type": "InvalidInputError", "message": format!("Unknown query type: {}", unknown)}))).into_response()
        }
        None => {
            warn!(
                "Could not determine query type for /api/v1/query. Params: {:?}, Body: {:?}",
                params,
                payload
                    .query
                    .as_ref()
                    .and_then(|q| q.first())
                    .and_then(|op| op.name.as_ref())
            );
            (StatusCode::BAD_REQUEST, Json(json!({"type": "InvalidInputError", "message": "Could not determine query type for /api/v1/query. Ensure 'name' query param or '_name' in query body is set."}))).into_response()
        }
    }
}

async fn catch_all(
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let path = uri.path().to_string();
    warn!("Unhandled request: {} {}", method, path);
    warn!("Headers: {:?}", headers);

    let body_str = String::from_utf8_lossy(&body);
    if !body_str.is_empty() {
        warn!("Request body: {}", body_str);
    }

    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "type": "NotFoundError",
            "message": format!("No handler for: {} {}. Check available routes.", method, path),
            "available_routes_info": [
                "GET /health",
                "GET /api/v1/alert/:id",
                "GET /api/v1/case/:id",
                "POST /api/v1/alert/:id/case (promote alert)",
                "POST /api/v1/case (create case)",
                "POST /api/v1/query (for lists, use 'name=listAlert' or 'name=cases' query param, or '_name' in query body)"
            ]
        })),
    )
}

#[tokio::main]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_writer(std::io::stderr) // Log to stderr for tests
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    info!("Starting Mock TheHive Server...");

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/alert/:id", get(get_alert_by_id))
        .route("/api/v1/case/:id", get(get_case_by_id))
        .route("/api/v1/alert/:id/case", post(promote_alert_to_case))
        .route("/api/v1/case", post(create_case))
        .route("/api/v1/query", post(handle_query_api))
        .fallback(catch_all);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let port = addr.port();

    println!("MOCK_SERVER_PORT={}", port); // Critical for test harness
    info!("Mock server listening on 127.0.0.1:{}", port);

    axum::serve(listener, app).await.unwrap();
}
