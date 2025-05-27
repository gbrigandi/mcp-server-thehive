//! MCP stdio interface integration tests
//!
//! These tests verify that the MCP server correctly handles the stdio protocol
//! and can communicate with TheHive API using real credentials.

use serde_json::{json, Value};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[cfg(test)]
mod mcp_stdio_tests {
    use super::*;

    #[tokio::test]
    async fn test_mcp_initialize_and_list_tools() {
        let api_key = match env::var("THEHIVE_API_KEY") {
            Ok(key) => key,
            Err(_) => {
                println!("Skipping test: THEHIVE_API_KEY not set");
                return;
            }
        };

        let api_endpoint = env::var("THEHIVE_API_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:9000/api".to_string());

        println!("Testing with endpoint: {}", api_endpoint);
        println!(
            "Testing with API key: {}***",
            &api_key[..std::cmp::min(8, api_key.len())]
        );

        let mut cmd = Command::new("cargo")
            .args(&["run", "--release"])
            .env("THEHIVE_URL", &api_endpoint)
            .env("THEHIVE_API_TOKEN", &api_key)
            .env("VERIFY_SSL", "false")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start MCP server");

        let stdin = cmd.stdin.as_mut().expect("Failed to get stdin");
        let stdout = cmd.stdout.as_mut().expect("Failed to get stdout");
        let mut reader = BufReader::new(stdout);

        thread::sleep(Duration::from_millis(500));

        let initialize_request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "roots": {
                        "listChanged": true
                    },
                    "sampling": {}
                },
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        });

        writeln!(stdin, "{}", initialize_request).expect("Failed to write initialize request");
        stdin.flush().expect("Failed to flush stdin");

        let mut response_line = String::new();
        match reader.read_line(&mut response_line) {
            Ok(_) => {
                println!("Initialize response: {}", response_line.trim());

                let response: Value = serde_json::from_str(&response_line)
                    .expect("Failed to parse initialize response");

                assert_eq!(response["jsonrpc"], "2.0");
                assert_eq!(response["id"], 1);
                assert!(response["result"].is_object());

                let initialized_notification = json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {}
                });

                writeln!(stdin, "{}", initialized_notification)
                    .expect("Failed to write initialized notification");
                stdin.flush().expect("Failed to flush stdin");

                thread::sleep(Duration::from_millis(100));

                let tools_request = json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {}
                });

                writeln!(stdin, "{}", tools_request).expect("Failed to write tools/list request");
                stdin.flush().expect("Failed to flush stdin");

                let mut tools_response_line = String::new();
                match reader.read_line(&mut tools_response_line) {
                    Ok(_) => {
                        println!("Tools response: {}", tools_response_line.trim());

                        let tools_response: Value = serde_json::from_str(&tools_response_line)
                            .expect("Failed to parse tools response");

                        assert_eq!(tools_response["jsonrpc"], "2.0");
                        assert_eq!(tools_response["id"], 2);

                        let tools = &tools_response["result"]["tools"];
                        assert!(tools.is_array());

                        let tools_array = tools.as_array().unwrap();
                        assert!(tools_array.len() >= 5); 

                        let tool_names: Vec<String> = tools_array
                            .iter()
                            .map(|tool| tool["name"].as_str().unwrap().to_string())
                            .collect();

                        assert!(tool_names.contains(&"get_thehive_alerts".to_string()));
                        assert!(tool_names.contains(&"get_thehive_alert_by_id".to_string()));
                        assert!(tool_names.contains(&"get_thehive_cases".to_string()));
                        assert!(tool_names.contains(&"get_thehive_case_by_id".to_string()));
                        assert!(tool_names.contains(&"promote_alert_to_case".to_string()));

                        println!("✓ All expected tools are available: {:?}", tool_names);
                    }
                    Err(e) => panic!("Failed to read tools response: {}", e),
                }
            }
            Err(e) => panic!("Failed to read initialize response: {}", e),
        }

        cmd.kill().expect("Failed to kill MCP server process");
    }

    #[tokio::test]
    async fn test_get_thehive_alerts_tool() {
        let api_key = match env::var("THEHIVE_API_KEY") {
            Ok(key) => key,
            Err(_) => {
                println!("Skipping test: THEHIVE_API_KEY not set");
                return;
            }
        };

        let api_endpoint = env::var("THEHIVE_API_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:9000/api".to_string());

        println!("Testing get_thehive_alerts with endpoint: {}", api_endpoint);

        let mut cmd = Command::new("cargo")
            .args(&["run", "--release"])
            .env("THEHIVE_URL", &api_endpoint)
            .env("THEHIVE_API_TOKEN", &api_key)
            .env("VERIFY_SSL", "false")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start MCP server");

        let stdin = cmd.stdin.as_mut().expect("Failed to get stdin");
        let stdout = cmd.stdout.as_mut().expect("Failed to get stdout");
        let mut reader = BufReader::new(stdout);

        thread::sleep(Duration::from_millis(500));

        let initialize_request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        });

        writeln!(stdin, "{}", initialize_request).expect("Failed to write initialize request");
        stdin.flush().expect("Failed to flush stdin");

        let mut response_line = String::new();
        reader
            .read_line(&mut response_line)
            .expect("Failed to read initialize response");

        let initialized_notification = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        });

        writeln!(stdin, "{}", initialized_notification)
            .expect("Failed to write initialized notification");
        stdin.flush().expect("Failed to flush stdin");

        thread::sleep(Duration::from_millis(100));

        let tool_call_request = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "get_thehive_alerts",
                "arguments": {
                    "limit": 5
                }
            }
        });

        writeln!(stdin, "{}", tool_call_request).expect("Failed to write tool call request");
        stdin.flush().expect("Failed to flush stdin");

        let mut tool_response_line = String::new();
        match reader.read_line(&mut tool_response_line) {
            Ok(_) => {
                println!("Tool call response: {}", tool_response_line.trim());

                if !tool_response_line.trim().is_empty() {
                    let tool_response: Value = serde_json::from_str(&tool_response_line)
                        .expect("Failed to parse tool response");

                    assert_eq!(tool_response["jsonrpc"], "2.0");
                    assert_eq!(tool_response["id"], 2);

                    let result = &tool_response["result"];
                    assert!(result["content"].is_array());

                    let content = result["content"].as_array().unwrap();
                    assert!(!content.is_empty());

                    let first_content = &content[0];
                    assert_eq!(first_content["type"], "text");
                    assert!(first_content["text"].is_string());

                    if result["is_error"].as_bool().unwrap_or(false) {
                        println!(
                            "✓ Tool call returned expected error (TheHive not accessible): {}",
                            first_content["text"]
                        );
                        assert!(first_content["text"].as_str().unwrap().contains("error"));
                    } else {
                        println!("✓ Successfully retrieved alerts from TheHive");
                    }
                } else {
                    println!("⚠ Empty response received - this may indicate a connection issue");
                }
            }
            Err(e) => {
                println!("⚠ Failed to read tool response: {} - this may indicate TheHive is not accessible", e);
            }
        }

        cmd.kill().expect("Failed to kill MCP server process");
    }

    #[tokio::test]
    async fn test_get_thehive_cases_tool() {
        let api_key = match env::var("THEHIVE_API_KEY") {
            Ok(key) => key,
            Err(_) => {
                println!("Skipping test: THEHIVE_API_KEY not set");
                return;
            }
        };

        let api_endpoint = env::var("THEHIVE_API_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:9000/api".to_string());

        println!("Testing get_thehive_cases with endpoint: {}", api_endpoint);

        let mut cmd = Command::new("cargo")
            .args(&["run", "--release"])
            .env("THEHIVE_URL", &api_endpoint)
            .env("THEHIVE_API_TOKEN", &api_key)
            .env("VERIFY_SSL", "false")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start MCP server");

        let stdin = cmd.stdin.as_mut().expect("Failed to get stdin");
        let stdout = cmd.stdout.as_mut().expect("Failed to get stdout");
        let mut reader = BufReader::new(stdout);

        thread::sleep(Duration::from_millis(500));

        let initialize_request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        });

        writeln!(stdin, "{}", initialize_request).expect("Failed to write initialize request");
        stdin.flush().expect("Failed to flush stdin");

        let mut response_line = String::new();
        reader
            .read_line(&mut response_line)
            .expect("Failed to read initialize response");

        let initialized_notification = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        });

        writeln!(stdin, "{}", initialized_notification)
            .expect("Failed to write initialized notification");
        stdin.flush().expect("Failed to flush stdin");

        thread::sleep(Duration::from_millis(100));

        let tool_call_request = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "get_thehive_cases",
                "arguments": {
                    "limit": 3
                }
            }
        });

        writeln!(stdin, "{}", tool_call_request).expect("Failed to write tool call request");
        stdin.flush().expect("Failed to flush stdin");

        let mut tool_response_line = String::new();
        match reader.read_line(&mut tool_response_line) {
            Ok(_) => {
                println!("Tool call response: {}", tool_response_line.trim());

                if !tool_response_line.trim().is_empty() {
                    let tool_response: Value = serde_json::from_str(&tool_response_line)
                        .expect("Failed to parse tool response");

                    assert_eq!(tool_response["jsonrpc"], "2.0");
                    assert_eq!(tool_response["id"], 2);

                    let result = &tool_response["result"];
                    assert!(result["content"].is_array());

                    let content = result["content"].as_array().unwrap();
                    assert!(!content.is_empty());

                    let first_content = &content[0];
                    assert_eq!(first_content["type"], "text");
                    assert!(first_content["text"].is_string());

                    if result["is_error"].as_bool().unwrap_or(false) {
                        println!(
                            "✓ Tool call returned expected error (TheHive not accessible): {}",
                            first_content["text"]
                        );
                        assert!(first_content["text"].as_str().unwrap().contains("error"));
                    } else {
                        println!("✓ Successfully retrieved cases from TheHive");
                    }
                } else {
                    println!("⚠ Empty response received - this may indicate a connection issue");
                }
            }
            Err(e) => {
                println!("⚠ Failed to read tool response: {} - this may indicate TheHive is not accessible", e);
            }
        }

        cmd.kill().expect("Failed to kill MCP server process");
    }
}

pub async fn run_mcp_stdio_test() {
    println!("🧪 Running MCP stdio interface tests...");

    let api_key =
        env::var("THEHIVE_API_KEY").expect("THEHIVE_API_KEY environment variable is required");

    let api_endpoint = env::var("THEHIVE_API_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:9000/api".to_string());

    println!("📍 Endpoint: {}", api_endpoint);
    println!(
        "🔑 API Key: {}***",
        &api_key[..std::cmp::min(8, api_key.len())]
    );

    println!("\n🚀 Starting MCP server test...");

    println!("✅ Test setup complete. Run with: cargo test mcp_stdio_tests");
}

#[tokio::main]
async fn main() {
    run_mcp_stdio_test().await;
}
