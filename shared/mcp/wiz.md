---
# Reusable Wiz MCP definition for any gh-aw workflow:
#   imports:
#     - n-drobyshevski/wiz-connector/shared/mcp/wiz.md@v1
# Secrets: WIZ_CLIENT_ID, WIZ_CLIENT_SECRET, WIZ_DATACENTER (a read-only "Wiz MCP Integration").
mcp-servers:
  wiz:
    url: "https://mcp.app.wiz.io"
    headers:
      Wiz-Client-Id: "${{ secrets.WIZ_CLIENT_ID }}"
      Wiz-Client-Secret: "${{ secrets.WIZ_CLIENT_SECRET }}"
      Wiz-DataCenter: "${{ secrets.WIZ_DATACENTER }}"
    allowed: [discover, execute]
engine:
  mcp:
    tool-timeout: 3m
---

The `wiz` MCP server runs in Gateway mode: call `discover` to select a Wiz tool by name (for
example `list_code_repositories`, `list_findings`, `list_vulnerability_findings`,
`get_vulnerability_finding`), then `execute` to run it. Never call tools that create, update or
delete anything in Wiz.
