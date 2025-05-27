# MCP Server for TheHive

An MCP (Model Context Protocol) server that provides AI models and automation tools with access to TheHive incident response platform.

## Overview

This server acts as a bridge between MCP clients (like AI assistants) and TheHive, allowing them to:

- Retrieve and analyze security alerts
- Access case information
- Promote alerts to cases
- Perform incident response operations

## Features

### Available Tools

1. **get_thehive_alerts** - Retrieve a list of alerts from TheHive
   - Optional `limit` parameter (default: 100)
   - Returns formatted alert information including ID, title, severity, and status

2. **get_thehive_alert_by_id** - Get detailed information about a specific alert
   - Required `alert_id` parameter
   - Returns comprehensive alert details

3. **get_thehive_cases** - Retrieve a list of cases from TheHive
   - Optional `limit` parameter (default: 100)
   - Returns formatted case information

4. **get_thehive_case_by_id** - Get detailed information about a specific case
   - Required `case_id` parameter
   - Returns comprehensive case details

5. **promote_alert_to_case** - Promote an alert to a case
   - Required `alert_id` parameter
   - Returns information about the newly created case

6. **create_thehive_case** - Create a new case in TheHive
   - Required `title` and `description` parameters
   - Optional parameters: `severity`, `tags`, `tlp`, `pap`, `status`, `assignee`, `case_template`, `start_date`
   - Returns information about the newly created case

## Installation

### Prerequisites

- Access to a TheHive 5 instance
- Valid TheHive API token

### Downloading Pre-compiled Binaries

You can download pre-compiled binaries for various operating systems from the [GitHub Releases page](https://github.com/gbrigandi/mcp-server-thehive/releases). Download the appropriate binary for your system, make it executable, and place it in your desired location.

### Building from Source

```bash
git clone <repository-url>
cd mcp-server-thehive
cargo build --release
```

## Configuration

The server requires the following environment variables:

- `THEHIVE_URL` - TheHive API base URL (default: `http://localhost:9000/api`)
- `THEHIVE_API_TOKEN` - TheHive API token (required)
- `VERIFY_SSL` - Whether to verify SSL certificates (default: `false`)
- `RUST_LOG` - Logging level (optional, e.g., `debug`, `info`)

### Environment File

Create a `.env` file in the project root:

```env
THEHIVE_URL=https://your-thehive-instance.com/api
THEHIVE_API_TOKEN=your-api-token-here
VERIFY_SSL=true
RUST_LOG=info
```

### Getting a TheHive API Token

1. Log into your TheHive instance
2. Go to **User Settings** → **API Keys**
3. Click **Create API Key**
4. Copy the generated token and use it as `THEHIVE_API_TOKEN`

## Usage

### Running the Server

```bash
# Using cargo
cargo run

# Using the built binary
./target/release/mcp-server-thehive
```

### Integration with MCP Clients

The server communicates over stdio using the MCP protocol. Configure your MCP client to use this server:

```json
{
  "mcpServers": {
    "thehive": {
      "command": "/path/to/mcp-server-thehive",
      "env": {
        "THEHIVE_URL": "https://your-thehive-instance.com:9000/api",
        "THEHIVE_API_TOKEN": "your-api-token-here"
      }
    }
  }
}
```

## Examples

### Retrieving Recent Alerts

```json
{
  "method": "tools/call",
  "params": {
    "name": "get_thehive_alerts",
    "arguments": {
      "limit": 10
    }
  }
}
```

### Getting Alert Details

```json
{
  "method": "tools/call",
  "params": {
    "name": "get_thehive_alert_by_id",
    "arguments": {
      "alert_id": "~123456"
    }
  }
}
```

### Promoting an Alert to Case

```json
{
  "method": "tools/call",
  "params": {
    "name": "promote_alert_to_case",
    "arguments": {
      "alert_id": "~123456"
    }
  }
}
```

### Creating a New Case

```json
{
  "method": "tools/call",
  "params": {
    "name": "create_thehive_case",
    "arguments": {
      "title": "Potential Malware Outbreak",
      "description": "Multiple endpoints reporting suspicious process activity.",
      "severity": 3,
      "tags": ["malware", "endpoint", "epp"],
      "tlp": 2,
      "assignee": "soc_level2"
    }
  }
}
```

## Development

### Project Structure

```
mcp-server-thehive/
├── src/
│   ├── main.rs              # Main server implementation
│   ├── lib.rs               # Library exports
│   └── thehive/
│       ├── mod.rs           # Module declarations
│       ├── client.rs        # TheHive API client
│       └── error.rs         # Error types
├── tests/
│   ├── bin/
│   │   └── mock_thehive_server.rs # Mock TheHive API server for testing
│   ├── integration_test.rs    # Integration tests
│   └── mcp_stdio_test.rs      # Stdio interface tests
├── Cargo.toml               # Dependencies and metadata
└── README.md                # This file
```

### Dependencies

- **rmcp** - MCP protocol implementation
- **thehive-client** - TheHive API client library
- **tokio** - Async runtime
- **reqwest** - HTTP client
- **serde** - Serialization framework
- **tracing** - Logging and instrumentation

### Testing

The project includes a comprehensive suite of integration tests that leverage a mock TheHive server. This mock server simulates the TheHive API, allowing for isolated and repeatable testing of the MCP server's functionality without requiring a live TheHive instance.

**Running Tests:**

```bash
# Run all tests (including integration tests that use the mock server)
cargo test

# Run tests with verbose logging (includes MCP server and mock server logs)
RUST_LOG=debug MCP_SERVER_THEHIVE_VERBOSE_TEST_LOGS=true cargo test
```

## Security Considerations

- Store API tokens securely (use environment variables or secure credential stores)
- Never commit API tokens to version control
- Enable SSL verification in production environments
- Limit network access to TheHive instance
- Use least-privilege API tokens for TheHive access
- Monitor and log all API interactions
- Rotate API tokens regularly

## Troubleshooting

### Common Issues

1. **Connection Refused**
   - Verify `THEHIVE_URL` is correct
   - Check network connectivity to TheHive instance
   - Ensure TheHive is running and accessible

2. **Authentication Failed**
   - Verify `THEHIVE_API_TOKEN` is correct and not expired
   - Check if the API token has necessary permissions
   - Ensure the token is properly formatted

3. **SSL Certificate Errors**
   - Set `VERIFY_SSL=false` for testing (not recommended for production)
   - Install proper SSL certificates
   - Use valid certificate authority

### Logging

Enable debug logging for troubleshooting:

```bash
RUST_LOG=debug cargo run
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License
 
This project is licensed under the MIT License - see the LICENSE file for details.

## Related Projects

- [thehive-client-rs](https://github.com/gbrigandi/thehive-client-rs) - Rust client library for TheHive API
- [mcp-server-cortex](https://github.com/gbrigandi/mcp-server-cortex) - MCP server for Cortex
- [mcp-server-wazuh](https://github.com/gbrigandi/mcp-server-wazuh) - MCP server for Wazuh SIEM
