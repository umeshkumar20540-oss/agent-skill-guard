const fs = require('fs');
const path = require('path');

const RULES = [
  { id: 'hidden-bidi-unicode', severity: 'critical', msg: 'Hidden Unicode Bidi / Zero-Width character detected (classic Trojan Source / invisible prompt injection)', rx: /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/ },
  { id: 'remote-pipe-exec', severity: 'critical', msg: 'Remote code download piped directly to shell (curl/wget | sh/bash)', rx: /(?:curl|wget)\s+[^\n|]+\|\s*(?:sh|bash|zsh|pwsh|powershell)/i },
  { id: 'encoded-exec', severity: 'high', msg: 'Base64-decoded payload executed in shell/eval', rx: /(?:base64\s+-d|FromBase64String|atob\()[\s\S]{0,80}(?:\|\s*(?:sh|bash)|eval\s*\(|exec\s*\()/i },
  { id: 'prompt-override', severity: 'high', msg: 'Prompt-injection override phrase detected (ignore previous instructions / system override)', rx: /\b(?:ignore\s+(?:all\s+)?previous\s+instructions|disregard\s+system\s+prompt|exfiltrate|bypass\s+safety)\b/i },
  { id: 'sensitive-path-exfil', severity: 'high', msg: 'Reads sensitive credential/SSH/env paths alongside network command', rx: /(?:\.ssh\/id_rsa|\.aws\/credentials|\.env\b|keychain)[\s\S]{0,120}(?:curl|wget|fetch\(|http\.request|nc\s)/i },
  { id: 'unpinned-npx', severity: 'medium', msg: 'Unpinned npx -y package execution in MCP config (supply-chain risk if typo-squatted)', rx: /"command"\s*:\s*"npx"[\s\S]{0,80}"-y"/i }
];

const TARGET_NAMES = new Set(['SKILL.md', 'CLAUDE.md', 'AGENTS.md', '.cursorrules', '.windsurfrules', 'mcp.json', 'claude_desktop_config.json']);

function scanContent(content, filePath = 'inline') {
  const findings = [];
  const lines = content.split(/\r?\n/);

  for (const rule of RULES) {
    if (rule.rx.test(content)) {
      let lineNum = 1;
      for (let i = 0; i < lines.length; i++) {
        if (rule.rx.test(lines[i])) { lineNum = i + 1; break; }
      }
      findings.push({ file: filePath, line: lineNum, id: rule.id, severity: rule.severity, msg: rule.msg });
    }
  }
  return findings;
}

function scanDirectory(dir) {
  const findings = [];
  let filesScanned = 0;

  function walk(cur) {
    for (const entry of fs.readdirSync(cur, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      const full = path.join(cur, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (TARGET_NAMES.has(entry.name) || /\.(md|json)$/i.test(entry.name) && full.toLowerCase().includes('skill')) {
        filesScanned++;
        const text = fs.readFileSync(full, 'utf8');
        findings.push(...scanContent(text, path.relative(dir, full) || entry.name));
      }
    }
  }

  walk(path.resolve(dir));
  const riskScore = findings.reduce((s, f) => s + (f.severity === 'critical' ? 40 : f.severity === 'high' ? 25 : 10), 0);
  return { filesScanned, findingCount: findings.length, status: riskScore === 0 ? 'CLEAN' : riskScore >= 40 ? 'DANGEROUS' : 'WARNING', findings };
}

module.exports = { scanContent, scanDirectory };
