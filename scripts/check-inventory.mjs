import fs from 'node:fs';
import path from 'node:path';
import {trackedFiles} from './git-client.mjs';

const root = process.cwd();
const inventoryPath = path.join(root, 'evidence/FILE_INVENTORY.md');
const write = process.argv.includes('--write');
const gitFiles = trackedFiles(root);
const markdown = fs.existsSync(inventoryPath) ? fs.readFileSync(inventoryPath, 'utf8') : '';
const listed = [...markdown.matchAll(/^- `([^`]+)`$/gm)].map((match) => match[1]).sort((a, b) => a.localeCompare(b));
const missingFromInventory = gitFiles.filter((file) => !listed.includes(file));
const missingFromGit = listed.filter((file) => !gitFiles.includes(file));
const generated = [
  '# S2-001 tracked file inventory',
  '',
  `Generated from \`git ls-files\`; count: ${gitFiles.length}.`,
  'This list is authoritative for the committed tree. Missing screenshots/logs are intentionally absent rather than reported as present.',
  '',
  ...gitFiles.map((file) => `- \`${file}\``),
  '',
].join('\n');

if (write) {
  fs.writeFileSync(inventoryPath, generated);
  console.log(JSON.stringify({exitCode: 0, mode: 'write', trackedFiles: gitFiles.length, path: 'evidence/FILE_INVENTORY.md'}));
  process.exit(0);
}

const ok = missingFromInventory.length === 0 && missingFromGit.length === 0 && listed.length === gitFiles.length;
const result = {
  exitCode: ok ? 0 : 1,
  trackedFiles: gitFiles.length,
  listedFiles: listed.length,
  missingFromInventory,
  missingFromGit,
  inventoryPath: 'evidence/FILE_INVENTORY.md',
  source: 'git ls-files -z',
};
console.log(JSON.stringify(result, null, 2));
if (!ok) process.exit(1);
