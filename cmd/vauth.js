#!/usr/bin/env node
'use strict';

const Vvauth = require('../index');
const parseArgs = require('nyks/process/parseArgs');

// Command spelling is a CLI concern, not an SDK compatibility alias.
async function main(argv = process.argv.slice(2)) {
  if(argv[0] === 'run') {
    const args = argv.slice(1);
    if(args[0] === '--') args.shift();
    const command = args.shift();
    if(!command) throw new Error('Missing command for run');
    process.exitCode = await new Vvauth().Run(command, ...args);
    return;
  }
  const {args, dict} = parseArgs(argv);
  const enabled = value => value !== undefined && !['', 'false', '0'].includes(String(value).toLowerCase());
  const command = enabled(dict.gitlab) ? 'gitlab' : args.shift() || (dict.version ? 'version' : undefined);
  if(command === 'version') {
    process.stdout.write(Vvauth.Version() + '\n');
    return;
  }
  if(!['env', 'login', 'connect', 'dotenv', 'show', 'set', 'unset', 'install', 'gitlab'].includes(command))
    throw new Error('Usage: vauth <env|login|connect|run|dotenv|show|set|unset|install|version|gitlab>');
  if(Object.hasOwn(dict, 'ir://run'))
    throw new Error('Unsupported flag --ir://run');
  const param = (index, name) => index < args.length ? args[index] : dict[name];
  const client = new Vvauth();
  let result;
  switch(command) {
    case 'env': result = await client.Env(enabled(param(0, 'source')), enabled(param(1, 'renew'))); break;
    case 'login': await client.Login(enabled(param(0, 'source')), enabled(param(1, 'renew'))); return;
    case 'connect': result = await client.Connect(enabled(param(0, 'renew'))); break;
    case 'dotenv': await client.Dotenv(); return;
    case 'show': result = await client.Show(); break;
    case 'set':
      if(param(0, 'k') === undefined || param(1, 'v') === undefined) throw new Error('Missing parameter --k or --v');
      await client.Set(param(0, 'k'), param(1, 'v')); return;
    case 'unset':
      if(param(0, 'k') === undefined) throw new Error('Missing parameter --k');
      await client.Unset(param(0, 'k')); return;
    case 'install': await client.Install(); return;
    case 'gitlab': await client.Gitlab(); return;
  }
  if(result !== undefined && result !== '') {
    if(Object.hasOwn(dict, 'ir://json') || typeof result !== 'string')
      process.stdout.write(JSON.stringify(result) + (Object.hasOwn(dict, 'ir://json') ? '' : '\n'));
    else
      process.stdout.write(result);
  }
}

function start(argv) {
  return main(argv).catch(err => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  });
}

module.exports = start;
if(require.main === module)
  start();
