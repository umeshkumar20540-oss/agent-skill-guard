const readline = require('readline');
const { scanContent, scanDirectory } = require('./guard');

function startMcp() {
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  const send = obj => process.stdout.write(JSON.stringify(obj) + '\n');

  rl.on('line', line => {
    if (!line.trim()) return;
    let req;
    try { req = JSON.parse(line); } catch { return; }

    if (req.method === 'initialize') {
      return send({ jsonrpc: '2.0', id: req.id, result: { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'agent-skill-guard', version: '1.0.0' } } });
    }
    if (req.method === 'tools/list') {
      return send({
        jsonrpc: '2.0', id: req.id,
        result: {
          tools: [
            { name: 'scan_skill_text', description: 'Scan SKILL.md, CLAUDE.md, .cursorrules, or mcp.json text for hidden Unicode injection and malicious commands.', inputSchema: { type: 'object', properties: { content: { type: 'string' } }, required: ['content'] } },
            { name: 'scan_workspace', description: 'Audit a local directory of AI skills and MCP configs for supply-chain risks.', inputSchema: { type: 'object', properties: { dir: { type: 'string' } }, required: ['dir'] } }
          ]
        }
      });
    }
    if (req.method === 'tools/call') {
      const { name, arguments: args = {} } = req.params || {};
      if (name === 'scan_skill_text') {
        const findings = scanContent(args.content || '', 'mcp-input');
        return send({ jsonrpc: '2.0', id: req.id, result: { content: [{ type: 'text', text: JSON.stringify({ findings }, null, 2) }] } });
      }
      if (name === 'scan_workspace') {
        const out = scanDirectory(args.dir || '.');
        return send({ jsonrpc: '2.0', id: req.id, result: { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] } });
      }
    }
    if (req.id !== undefined) send({ jsonrpc: '2.0', id: req.id, error: { code: -32601, message: 'Method not found' } });
  });
}

module.exports = { startMcp };
