#!/usr/bin/env node

/**
 * Google Cloud Logging MCP Server
 * 
 * Provides tools for:
 * - Cloud Audit Logs queries
 * - VPC Flow Logs analysis
 * - Cloud DNS logs
 * - Application logs with filtering
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Logging } from "@google-cloud/logging";

// Initialize MCP server
const server = new Server({
  name: "gcp-logging-mcp",
  version: "1.0.0"
});

// Initialize Google Cloud Logging client
const logging = new Logging();

server.setRequestHandler("tools/call", async (request) => {
  const { name, arguments: args } = request;

  if (name === "query_logs") {
    return handleQueryLogs(args);
  } else if (name === "query_audit_logs") {
    return handleQueryAuditLogs(args);
  } else if (name === "query_vpc_flow_logs") {
    return handleQueryVPCFlowLogs(args);
  } else if (name === "query_dns_logs") {
    return handleQueryDNSLogs(args);
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
        name: "query_logs",
        description: "[GCP LOGGING] Query Cloud Logging with filter syntax. Examples: 'severity=ERROR', 'logName:cloudaudit', 'resource.type=gce_instance'",
        inputSchema: {
          type: "object",
          properties: {
            filter: { type: "string", description: "GCP filter syntax (severity=, logName:, resource.type=, jsonPayload.)" },
            hours_back: { type: "integer", default: 24, description: "Hours to look back" },
            max_results: { type: "integer", default: 100, description: "Maximum log entries to return" },
            project_id: { type: "string", description: "GCP project ID (optional)" }
          },
          required: ["filter"]
        }
      },
      {
        name: "query_audit_logs",
        description: "[GCP LOGGING] Query Cloud Audit Logs for IAM, resource changes, API calls",
        inputSchema: {
          type: "object",
          properties: {
            resource_type: { type: "string", description: "Resource type (gce_instance, storage_bucket, service_account, etc.)" },
            method_name: { type: "string", description: "API method name (e.g., 'compute.instances.delete')" },
            hours_back: { type: "integer", default: 24, description: "Hours to look back" },
            max_results: { type: "integer", default: 100, description: "Maximum entries to return" }
          }
        }
      },
      {
        name: "query_vpc_flow_logs",
        description: "[GCP LOGGING] Query VPC Flow Logs for network traffic analysis",
        inputSchema: {
          type: "object",
          properties: {
            subnet_name: { type: "string", description: "Subnet name to query" },
            src_ip: { type: "string", description: "Source IP (optional)" },
            dst_ip: { type: "string", description: "Destination IP (optional)" },
            protocol: { type: "string", description: "Protocol (TCP, UDP, ICMP, etc.)" },
            hours_back: { type: "integer", default: 24, description: "Hours to look back" },
            max_results: { type: "integer", default: 1000, description: "Maximum flow records to return" }
          }
        }
      },
      {
        name: "query_dns_logs",
        description: "[GCP LOGGING] Query Cloud DNS query logs",
        inputSchema: {
          type: "object",
          properties: {
            domain: { type: "string", description: "Domain to query" },
            query_type: { type: "string", description: "Query type (A, AAAA, MX, TXT, etc.)" },
            hours_back: { type: "integer", default: 24, description: "Hours to look back" },
            max_results: { type: "integer", default: 100, description: "Maximum records to return" }
          }
        }
      }
    ]
  };
});

// Handler implementations
async function handleQueryLogs(args) {
  try {
    const filter = args.filter || "";
    const hoursBack = args.hours_back || 24;
    const maxResults = args.max_results || 100;
    const projectId = args.project_id;

    // In production: query Cloud Logging API
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            filter,
            hours_back: hoursBack,
            max_results: maxResults,
            status: "Would query Cloud Logging",
            sample_filter: "severity=ERROR AND resource.type=gce_instance"
          }, null, 2)
        }
      ]
    };
  } catch (error) {
    return {
      isError: true,
      content: [{ type: "text", text: `Error: ${error.message}` }]
    };
  }
}

async function handleQueryAuditLogs(args) {
  try {
    const resourceType = args.resource_type || "";
    const methodName = args.method_name || "";
    const hoursBack = args.hours_back || 24;
    const maxResults = args.max_results || 100;

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            resource_type: resourceType,
            method_name: methodName,
            hours_back: hoursBack,
            max_results: maxResults,
            status: "Would query Cloud Audit Logs"
          }, null, 2)
        }
      ]
    };
  } catch (error) {
    return {
      isError: true,
      content: [{ type: "text", text: `Error: ${error.message}` }]
    };
  }
}

async function handleQueryVPCFlowLogs(args) {
  try {
    const subnetName = args.subnet_name || "";
    const srcIp = args.src_ip || "";
    const dstIp = args.dst_ip || "";
    const protocol = args.protocol || "";
    const hoursBack = args.hours_back || 24;
    const maxResults = args.max_results || 1000;

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            subnet_name: subnetName,
            src_ip: srcIp,
            dst_ip: dstIp,
            protocol,
            hours_back: hoursBack,
            max_results: maxResults,
            status: "Would query VPC Flow Logs"
          }, null, 2)
        }
      ]
    };
  } catch (error) {
    return {
      isError: true,
      content: [{ type: "text", text: `Error: ${error.message}` }]
    };
  }
}

async function handleQueryDNSLogs(args) {
  try {
    const domain = args.domain || "";
    const queryType = args.query_type || "";
    const hoursBack = args.hours_back || 24;
    const maxResults = args.max_results || 100;

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            domain,
            query_type: queryType,
            hours_back: hoursBack,
            max_results: maxResults,
            status: "Would query Cloud DNS logs"
          }, null, 2)
        }
      ]
    };
  } catch (error) {
    return {
      isError: true,
      content: [{ type: "text", text: `Error: ${error.message}` }]
    };
  }
}

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("GCP Logging MCP server running on stdio");
}

main().catch(console.error);
