#!/usr/bin/env node
const { scanDirectory } = require('../src/guard');
const { startMcp } = require('../src/mcp');

const [cmd, arg] = process.argv.slice(2);
if (cmd === 'mcp') {
  startMcp();
} else if (cmd === 'scan') {
  const res = scanDirectory(arg || '.');
  console.log(JSON.stringify(res, null, 2));
  if (res.status === 'DANGEROUS') process.exit(2);
} else {
  console.log('Usage:\n  agent-skill-guard scan <dir>\n  agent-skill-guard mcp');
}
