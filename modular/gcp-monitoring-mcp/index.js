#!/usr/bin/env node

/**
 * Google Cloud Monitoring MCP Server
 * 
 * Provides tools for:
 * - Metric queries (CPU, memory, network)
 * - Alert policy management
 * - Custom metrics and dashboards
 * - SLO tracking and alerts
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server({
  name: "gcp-monitoring-mcp",
  version: "1.0.0"
});

server.setRequestHandler("tools/call", async (request) => {
  const { name, arguments: args } = request;
  
  if (name === "query_metrics") {
    return { content: [{ type: "text", text: "Query metrics endpoint would be called" }] };
  }
  
  return {
    isError: true,
    content: [{ type: "text", text: `Unknown tool: ${name}` }]
  };
});

server.setRequestHandler("tools/list", async () => {
  return {
    tools: [
      {
        name: "query_metrics",
        description: "[GCP MONITORING] Query Cloud Monitoring metrics (CPU, memory, network, custom metrics)",
        inputSchema: {
          type: "object",
          properties: {
            metric_type: { type: "string", description: "Metric type (e.g., 'compute.googleapis.com/instance/cpu/utilization')" },
            resource_labels: { type: "object", description: "Resource labels to filter by" },
            hours_back: { type: "integer", default: 24, description: "Hours to look back" }
          },
          required: ["metric_type"]
        }
      }
    ]
  };
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("GCP Monitoring MCP server running on stdio");
}

main().catch(console.error);
