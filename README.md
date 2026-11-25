# 🔒 agent-skill-guard

**Audit third-party AI Agent Skills (`SKILL.md`, `CLAUDE.md`, `.cursorrules`) and `mcp.json` configs before your coding agent executes them.**

Zero external dependencies. Catches invisible Unicode/Bidi prompt injections, `curl | bash` payloads, credential exfiltration, and unpinned `npx -y` supply-chain risks.

## Quickstart
```bash
npx agent-skill-guard scan .
```

## MCP Configuration
```json
{
  "mcpServers": {
    "skill-guard": {
      "command": "npx",
      "args": ["agent-skill-guard", "mcp"]
    }
  }
}
```

## License
MIT — More free privacy-first tools at [minimaxtools.com](https://minimaxtools.com).
