use serde_json::{json, Value};
use std::env;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

const THEHIVE_API_TOKEN: &str = "test_token"; 

struct TestContext {
    mcp_server_process: Child,
    mcp_stdin: std::process::ChildStdin,
    mcp_stdout: BufReader<std::process::ChildStdout>,
    _mcp_stderr_logger_thread: Option<thread::JoinHandle<()>>, 
    mock_server_process: Child,
    mcp_request_id: i64,
}

impl TestContext {
    async fn setup() -> Self {
        println!("Starting mock_thehive_server...");
        let mut mock_server_process = Command::new("cargo")
            .args(&["run", "--bin", "mock_thehive_server"])
            .env("RUST_LOG", "warn") 
            .stdout(Stdio::piped()) 
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start mock_thehive_server. Ensure it's defined as [[bin]] in Cargo.toml and compiles.");

        let mock_server_stdout_pipe = mock_server_process
            .stdout
            .take()
            .expect("Failed to capture mock_server stdout.");
        let mut mock_stdout_reader = BufReader::new(mock_server_stdout_pipe);
        let mut port_line = String::new();
        let mut mock_server_port: u16 = 0;
        let mut port_found = false;

        for _attempt in 0..20 {
            match mock_stdout_reader.read_line(&mut port_line) {
                Ok(0) => {
                    println!("Mock server stdout EOF before port line found.");
                    break;
                }
                Ok(_) => {
                    if port_line.starts_with("MOCK_SERVER_PORT=") {
                        mock_server_port = port_line
                            .trim_start_matches("MOCK_SERVER_PORT=")
                            .trim()
                            .parse()
                            .expect("Failed to parse port from mock_server stdout.");
                        port_found = true;
                        println!("Mock server reported port: {}", mock_server_port);
                        break;
                    }
                    println!("Mock server stdout (ignoring): {}", port_line.trim());
                    port_line.clear(); 
                }
                Err(e) => {
                    println!(
                        "Error reading mock_server stdout: {}. Assuming server died.",
                        e
                    );
                    break;
                }
            }
            thread::sleep(Duration::from_millis(50));
        }

        if !port_found {
            let mut mock_stderr_output = String::new();
            if let Some(mut stderr_pipe) = mock_server_process.stderr.take() {
                let _ = stderr_pipe.read_to_string(&mut mock_stderr_output);
            }
            panic!(
                "Could not determine mock server port. Stderr: {}",
                mock_stderr_output
            );
        }

        let mock_server_base_url = format!("http://127.0.0.1:{}", mock_server_port);
        let mock_server_api_url = format!("{}/api", mock_server_base_url);

        println!(
            "Waiting for mock_thehive_server to be healthy at {}/health...",
            mock_server_base_url
        );
        let client = reqwest::Client::new();
        let mut mock_ready = false;
        for i in 0..60 {
            match client
                .get(format!("{}/health", mock_server_base_url))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    mock_ready = true;
                    println!("Mock server is healthy.");
                    break;
                }
                Ok(resp) => {
                    println!(
                        "Mock server health check attempt {} failed with status: {}",
                        i + 1,
                        resp.status()
                    );
                }
                Err(e) => {
                    println!("Mock server health check attempt {} failed: {}", i + 1, e);
                }
            }
            thread::sleep(Duration::from_millis(500));
        }
        if !mock_ready {
            let mut mock_stderr_output = String::new();
            if let Some(mut stderr_pipe) = mock_server_process.stderr.take() {
                match stderr_pipe.read_to_string(&mut mock_stderr_output) {
                    Ok(bytes_read) => {
                        println!("Read {} bytes from mock server stderr.", bytes_read);
                    }
                    Err(e) => {
                        eprintln!("Error reading mock server stderr: {}", e);
                    }
                }
            } else {
                println!("Mock server stderr was already taken or not available.");
            }
            panic!(
                "Mock server did not become healthy after 30 seconds. Stderr: <{}>",
                mock_stderr_output.trim()
            );
        }

        println!("Starting mcp-server-thehive...");
        let mut mcp_server_command = Command::new("cargo");
        mcp_server_command
            .args(&["run", "--bin", "mcp-server-thehive"])
            .env("THEHIVE_URL", &mock_server_api_url) 
            .env("THEHIVE_API_TOKEN", THEHIVE_API_TOKEN)
            .env("VERIFY_SSL", "false")
            .env("RUST_LOG", "debug") 
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if env::var("MCP_SERVER_THEHIVE_VERBOSE_TEST_LOGS").is_ok() {
            mcp_server_command.stderr(Stdio::inherit());
        }

        let mut mcp_server_process = mcp_server_command.spawn().expect(
            "Failed to start mcp-server-thehive. Ensure it's the main binary and compiles.",
        );

        let mcp_stdin = mcp_server_process
            .stdin
            .take()
            .expect("Failed to get mcp_server stdin");
        let mcp_stdout = BufReader::new(
            mcp_server_process
                .stdout
                .take()
                .expect("Failed to get mcp_server stdout"),
        );

        let mut mcp_stderr_logger_thread = None;
        if env::var("MCP_SERVER_THEHIVE_VERBOSE_TEST_LOGS").is_err() {
            if let Some(mcp_stderr_pipe) = mcp_server_process.stderr.take() {
                mcp_stderr_logger_thread = Some(thread::spawn(move || {
                    let reader = BufReader::new(mcp_stderr_pipe);
                    for line in reader.lines() {
                        eprintln!("[MCP_SERVER_STDERR] {}", line.unwrap_or_default());
                    }
                }));
            }
        }

        println!("MCP server started. Initializing protocol...");
        let mut ctx = TestContext {
            mcp_server_process,
            mcp_stdin,
            mcp_stdout,
            _mcp_stderr_logger_thread: mcp_stderr_logger_thread,
            mock_server_process,
            mcp_request_id: 0,
        };

        ctx.next_id();
        let init_req = json!({
            "jsonrpc": "2.0",
            "id": ctx.mcp_request_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "integration-test-client", "version": "0.1.0"}
            }
        });
        ctx.send_request(&init_req);
        let init_resp = ctx.read_response();
        assert_eq!(
            init_resp["id"], ctx.mcp_request_id,
            "Initialize response ID mismatch. Response: {:?}",
            init_resp
        );
        assert!(
            init_resp["result"].is_object(),
            "Initialize failed: {:?}",
            init_resp
        );
        println!("MCP protocol initialized.");

        let initialized_notif = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        });
        ctx.send_request(&initialized_notif);
        thread::sleep(Duration::from_millis(300)); 

        ctx
    }

    fn teardown(mut self) {
        println!("Tearing down test context...");
        let exit_notif = json!({
            "jsonrpc": "2.0",
            "method": "exit"
        });
        if writeln!(self.mcp_stdin, "{}", exit_notif).is_ok() {
            let _ = self.mcp_stdin.flush();
        }

        thread::sleep(Duration::from_millis(100));

        println!(
            "Killing MCP server process (PID: {})...",
            self.mcp_server_process.id()
        );
        if let Err(e) = self.mcp_server_process.kill() {
            eprintln!("Failed to kill MCP server process: {}", e);
        }
        if let Err(e) = self.mcp_server_process.wait() {
            eprintln!("Error waiting for MCP server process: {}", e);
        }
        println!("MCP server process terminated.");

        println!(
            "Killing mock server process (PID: {})...",
            self.mock_server_process.id()
        );
        if let Err(e) = self.mock_server_process.kill() {
            eprintln!("Failed to kill mock server process: {}", e);
        }
        if let Err(e) = self.mock_server_process.wait() {
            eprintln!("Error waiting for mock server process: {}", e);
        }
        println!("Mock server process terminated.");
        println!("Teardown complete.");
    }

    fn next_id(&mut self) -> i64 {
        self.mcp_request_id += 1;
        self.mcp_request_id
    }

    fn send_request(&mut self, request: &Value) {
        writeln!(self.mcp_stdin, "{}", request).expect("Failed to write to mcp_server stdin");
        self.mcp_stdin
            .flush()
            .expect("Failed to flush mcp_server stdin");
    }

    fn read_response(&mut self) -> Value {
        let mut line = String::new();
        match self.mcp_stdout.read_line(&mut line) {
            Ok(0) => panic!("MCP server closed stdout unexpectedly."),
            Ok(_) => {
                serde_json::from_str(&line).unwrap_or_else(|e| {
                    panic!(
                        "Failed to parse JSON response from mcp_server: {}. Line: '{}'",
                        e,
                        line.trim()
                    )
                })
            }
            Err(e) => panic!("Failed to read from mcp_server stdout: {}", e),
        }
    }

    fn call_tool(&mut self, tool_name: &str, args: Value) -> Value {
        self.next_id();
        let req = json!({
            "jsonrpc": "2.0",
            "id": self.mcp_request_id,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": args
            }
        });
        self.send_request(&req);
        let resp = self.read_response();
        assert_eq!(
            resp["id"], self.mcp_request_id,
            "Tool call response ID mismatch. Response: {:?}",
            resp
        );

        if resp.get("error").is_some() {
            panic!("Tool call resulted in JSON-RPC error: {:?}", resp["error"]);
        }
        resp["result"].clone()
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_list_tools() {
        let mut ctx = TestContext::setup().await;

        ctx.next_id();
        let list_tools_req = json!({
            "jsonrpc": "2.0",
            "id": ctx.mcp_request_id,
            "method": "tools/list",
            "params": {}
        });
        ctx.send_request(&list_tools_req);
        let resp = ctx.read_response();

        assert_eq!(resp["id"], ctx.mcp_request_id);
        let tools = resp["result"]["tools"]
            .as_array()
            .expect("tools should be an array");

        let expected_tools = [
            "get_thehive_alerts",
            "get_thehive_alert_by_id",
            "get_thehive_cases",
            "get_thehive_case_by_id",
            "promote_alert_to_case",
            "create_thehive_case",
        ];
        for expected_tool_name in expected_tools.iter() {
            assert!(
                tools
                    .iter()
                    .any(|t| t["name"].as_str().unwrap() == *expected_tool_name),
                "Expected tool {} not found",
                expected_tool_name
            );
        }
        assert_eq!(
            tools.len(),
            expected_tools.len(),
            "Mismatch in number of tools. Found: {:?}, Expected: {:?}",
            tools,
            expected_tools
        );

        ctx.teardown();
    }

    #[tokio::test]
    async fn test_get_thehive_alerts_tool() {
        let mut ctx = TestContext::setup().await;
        let result = ctx.call_tool("get_thehive_alerts", json!({"limit": 5}));

        assert_eq!(
            result["isError"].as_bool(),
            Some(false),
            "Tool call should not be an error. Result: {:?}",
            result
        );
        let content = result["content"]
            .as_array()
            .expect("Content should be an array");
        assert_eq!(
            content.len(),
            2,
            "Expected two content items for the two mock alerts"
        );
        assert_eq!(content[0]["type"], "text");
        assert_eq!(content[1]["type"], "text");
        let alert_texts = vec![
            content[0]["text"].as_str().unwrap(),
            content[1]["text"].as_str().unwrap(),
        ];

        let has_alert_001 = alert_texts
            .iter()
            .any(|text| text.contains("Alert ID: alert_001"));
        let has_alert_002 = alert_texts
            .iter()
            .any(|text| text.contains("Alert ID: alert_002"));
        assert!(has_alert_001, "Should contain alert_001");
        assert!(has_alert_002, "Should contain alert_002");

        let alert_001_text = alert_texts
            .iter()
            .find(|text| text.contains("Alert ID: alert_001"))
            .unwrap();
        assert!(alert_001_text.contains("Title: Suspicious Outbound Connection"));
        assert!(alert_001_text.contains("Severity: 3 (High)"));
        assert!(alert_001_text.contains("Status: New"));
        assert!(alert_001_text.contains("Source: SIEM"));

        let alert_002_text = alert_texts
            .iter()
            .find(|text| text.contains("Alert ID: alert_002"))
            .unwrap();
        assert!(alert_002_text.contains("Title: Phishing Email Reported by User"));
        assert!(alert_002_text.contains("Severity: 2 (Medium)"));
        assert!(alert_002_text.contains("Status: Imported"));
        assert!(alert_002_text.contains("Source: UserReport"));
    }

    #[tokio::test]
    async fn test_get_thehive_alert_by_id_tool_found() {
        let mut ctx = TestContext::setup().await;
        let result = ctx.call_tool("get_thehive_alert_by_id", json!({"alert_id": "alert_001"}));

        assert_eq!(
            result["isError"].as_bool(),
            Some(true),
            "Tool call should be an error. Result: {:?}",
            result
        );
        let content = result["content"]
            .as_array()
            .expect("Content should be an array");
        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["type"], "text");
        let text = content[0]["text"].as_str().unwrap();
        assert!(text.contains("Error retrieving alert alert_001 from TheHive"));

        ctx.teardown();
    }

    #[tokio::test]
    async fn test_get_thehive_alert_by_id_tool_not_found() {
        let mut ctx = TestContext::setup().await;
        let result = ctx.call_tool(
            "get_thehive_alert_by_id",
            json!({"alert_id": "non_existent_alert"}),
        );

        assert_eq!(
            result["isError"].as_bool(),
            Some(true),
            "Tool call should be an error for non-existent ID. Result: {:?}",
            result
        );
        let content = result["content"]
            .as_array()
            .expect("Content should be an array");
        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["type"], "text");
        let text = content[0]["text"].as_str().unwrap();
        assert!(text.contains("Error retrieving alert non_existent_alert from TheHive"));

        ctx.teardown();
    }

    #[tokio::test]
    async fn test_get_thehive_cases_tool() {
        let mut ctx = TestContext::setup().await;
        let result = ctx.call_tool("get_thehive_cases", json!({"limit": 3}));

        assert_eq!(
            result["isError"].as_bool(),
            Some(false),
            "Tool call should not be an error. Result: {:?}",
            result
        );
        let content = result["content"]
            .as_array()
            .expect("Content should be an array");
        assert_eq!(content[0]["type"], "text");
        let case_text = content[0]["text"].as_str().unwrap();
        assert!(case_text.contains("Case ID: case_001"));
        assert!(case_text.contains("Case Number: 1"));
        assert!(case_text.contains("Title: Initial Phishing Investigation"));
        assert!(case_text.contains("Severity: 2 (Medium)"));
        assert!(case_text.contains("Status: InProgress"));
        assert!(case_text.contains("Assignee: analyst1"));
        ctx.teardown();
    }

    #[tokio::test]
    async fn test_get_thehive_case_by_id_tool_found() {
        let mut ctx = TestContext::setup().await;
        let result = ctx.call_tool("get_thehive_case_by_id", json!({"case_id": "case_001"}));

        assert_eq!(
            result["isError"].as_bool(),
            Some(true),
            "Tool call should be an error. Result: {:?}",
            result
        );
        let content = result["content"]
            .as_array()
            .expect("Content should be an array");
        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["type"], "text");
        let text = content[0]["text"].as_str().unwrap();
        assert!(text.contains("Error retrieving case case_001 from TheHive"));

        ctx.teardown();
    }

    #[tokio::test]
    async fn test_promote_alert_to_case_tool_success() {
        let mut ctx = TestContext::setup().await;
        let result = ctx.call_tool("promote_alert_to_case", json!({"alert_id": "alert_002"}));

        assert_eq!(
            result["isError"].as_bool(),
            Some(true),
            "Tool call should be an error. Result: {:?}",
            result
        );
        let content = result["content"]
            .as_array()
            .expect("Content should be an array");
        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["type"], "text");
        let text = content[0]["text"].as_str().unwrap();
        assert!(text.contains("Error promoting alert alert_002 to case"));

        ctx.teardown();
    }

    #[tokio::test]
    async fn test_promote_alert_to_case_tool_alert_not_found() {
        let mut ctx = TestContext::setup().await;
        let result = ctx.call_tool(
            "promote_alert_to_case",
            json!({"alert_id": "non_existent_alert_for_promotion"}),
        );

        assert_eq!(
            result["isError"].as_bool(),
            Some(true),
            "Tool call should be an error. Result: {:?}",
            result
        );
        let content = result["content"]
            .as_array()
            .expect("Content should be an array");
        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["type"], "text");
        let text = content[0]["text"].as_str().unwrap();
        assert!(text.contains("Error promoting alert non_existent_alert_for_promotion to case"));

        ctx.teardown();
    }
}
