# Context 7 MCP Server

Advanced data analysis server using Model Context Protocol (MCP) for Context 7 methodology.

## Features

- **Advanced Pattern Analysis**: Detect complex patterns and anomalies in data
- **Sentiment Analysis**: Analyze emotional context and sentiment scores  
- **Semantic Analysis**: Extract concepts, relationships, and themes
- **Predictive Analytics**: Forecast trends and future patterns
- **Context Storage**: Maintain analysis history and insights
- **Report Generation**: Create comprehensive analysis reports

## Installation

```bash
cd mcp-servers
npm install
```

## Usage

### Start the server
```bash
npm start
```

### Available Tools

1. **analyze_context7**: Perform Context 7 analysis
2. **get_context7_insights**: Retrieve stored insights
3. **store_context7_data**: Store data in knowledge base
4. **generate_context7_report**: Generate analysis reports

## Integration with VS Code

To use this MCP server in VS Code, add it to your VS Code settings:

```json
{
  "mcp.servers": {
    "context7": {
      "command": "node",
      "args": ["D:\\vault_dev\\mcp-servers\\index.js"],
      "env": {}
    }
  }
}
```

## Examples

### Analyze Data
```javascript
{
  "data": "User login patterns show irregular activity",
  "analysisType": "pattern",
  "contextId": "security_analysis_001"
}
```

### Get Insights
```javascript
{
  "query": "security patterns",
  "limit": 5
}
```

### Generate Report
```javascript
{
  "dataSet": ["data1", "data2", "data3"],
  "reportType": "detailed"
}
```
