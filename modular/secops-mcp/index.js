#!/usr/bin/env node

/**
 * Google SecOps (Chronicle) MCP Server
 * 
 * Provides tools for:
 * - UDM search with natural language translation
 * - YARA-L rule discovery and testing
 * - Detection alerts and investigation
 * - Case management
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import axios from "axios";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Configuration
const SECOPS_PROJECT_ID = process.env.SECOPS_PROJECT_ID || "";
const SECOPS_CUSTOMER_ID = process.env.SECOPS_CUSTOMER_ID || "";
const SECOPS_REGION = process.env.SECOPS_REGION || "us";
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.0-flash-001";

const SECOPS_V1_BASE = `https://${SECOPS_REGION}-chronicle.googleapis.com/v1/projects/${SECOPS_PROJECT_ID}/locations/${SECOPS_REGION}/instances/${SECOPS_CUSTOMER_ID}`;
const SECOPS_V1BETA_BASE = `https://${SECOPS_REGION}-chronicle.googleapis.com/v1beta/projects/${SECOPS_PROJECT_ID}/locations/${SECOPS_REGION}/instances/${SECOPS_CUSTOMER_ID}`;

// Initialize MCP server
const server = new Server({
  name: "secops-mcp",
  version: "1.0.0"
});

/**
 * Tool: Search UDM with natural language
 */
server.setRequestHandler("tools/call", async (request) => {
  const { name, arguments: args } = request;

  if (name === "search_udm") {
    return handleSearchUDM(args);
  } else if (name === "list_rules") {
    return handleListRules(args);
  } else if (name === "list_detections") {
    return handleListDetections(args);
  } else if (name === "get_case") {
    return handleGetCase(args);
  } else if (name === "list_cases") {
    return handleListCases(args);
  } else if (name === "create_case") {
    return handleCreateCase(args);
  }

  return {
    isError: true,
    content: [{ type: "text", text: `Unknown tool: ${name}` }]
  };
});

/**
 * Tool: List available tools
 */
server.setRequestHandler("tools/list", async () => {
  return {
    tools: [
      {
        name: "search_udm",
        description: "[SECOPS] Search UDM for security events. Translates natural language to UDM queries. Examples: 'user logins from China', 'malware detections', 'failed authentication attempts'",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string", description: "Natural language query or direct UDM query" },
            hours_back: { type: "integer", default: 24, description: "Hours to search back" },
            max_results: { type: "integer", default: 100, description: "Maximum results to return" }
          },
          required: ["query"]
        }
      },
      {
        name: "list_rules",
        description: "[SECOPS] List YARA-L detection rules with filtering",
        inputSchema: {
          type: "object",
          properties: {
            filter: { type: "string", description: "Filter by rule name, category, or severity" },
            limit: { type: "integer", default: 100, description: "Maximum rules to return" }
          }
        }
      },
      {
        name: "list_detections",
        description: "[SECOPS] List recent detection alerts",
        inputSchema: {
          type: "object",
          properties: {
            hours_back: { type: "integer", default: 24, description: "Hours to look back" },
            severity: { type: "string", description: "Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)" },
            limit: { type: "integer", default: 100, description: "Maximum detections to return" }
          }
        }
      },
      {
        name: "list_cases",
        description: "[SECOPS SOAR] List security investigation cases",
        inputSchema: {
          type: "object",
          properties: {
            state: { type: "string", description: "Filter by state (OPEN, CLOSED, RESOLVED)" },
            limit: { type: "integer", default: 50, description: "Maximum cases to return" }
          }
        }
      },
      {
        name: "get_case",
        description: "[SECOPS SOAR] Get details of a specific case",
        inputSchema: {
          type: "object",
          properties: {
            case_id: { type: "string", description: "The case ID" }
          },
          required: ["case_id"]
        }
      },
      {
        name: "create_case",
        description: "[SECOPS SOAR] Create a new security investigation case",
        inputSchema: {
          type: "object",
          properties: {
            name: { type: "string", description: "Case name" },
            description: { type: "string", description: "Case description" },
            severity: { type: "string", description: "Severity (LOW, MEDIUM, HIGH, CRITICAL)" }
          },
          required: ["name"]
        }
      }
    ]
  };
});

// Handler implementations
async function handleSearchUDM(args) {
  try {
    const query = args.query || "";
    const hoursBack = args.hours_back || 24;
    const maxResults = args.max_results || 100;

    // For demo: return sample data
    // In production, translate NL query to UDM and call SecOps API
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            query,
            hours_back: hoursBack,
            max_results: maxResults,
            status: "Query would be sent to SecOps UDM search API",
            sample_udm: "metadata.event_type = \"USER_LOGIN\" AND security_result.action = \"ALLOW\""
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

async function handleListRules(args) {
  try {
    const filter = args.filter || "";
    const limit = args.limit || 100;

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            filter,
            limit,
            status: "Would list YARA-L rules from SecOps",
            example_rules: [
              "ATI High Priority Rule Match for File IoCs",
              "Suspicious PowerShell Execution",
              "Credential Dumping Attempt"
            ]
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

async function handleListDetections(args) {
  try {
    const hoursBack = args.hours_back || 24;
    const severity = args.severity || "";
    const limit = args.limit || 100;

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            hours_back: hoursBack,
            severity,
            limit,
            status: "Would list detection alerts from SecOps"
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

async function handleListCases(args) {
  try {
    const state = args.state || "";
    const limit = args.limit || 50;

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            state,
            limit,
            status: "Would list SOAR cases",
            sample_cases: 50
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

async function handleGetCase(args) {
  try {
    const caseId = args.case_id || "";

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            case_id: caseId,
            status: "Would fetch case details from SOAR"
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

async function handleCreateCase(args) {
  try {
    const name = args.name || "";
    const description = args.description || "";
    const severity = args.severity || "MEDIUM";

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            name,
            description,
            severity,
            status: "Case would be created in SOAR",
            case_id: `case-${Date.now()}`
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
  console.error("SecOps MCP server running on stdio");
}

main().catch(console.error);
