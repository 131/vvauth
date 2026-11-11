'use strict';

const assert = require('node:assert/strict');
const {test} = require('node:test');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const {execFile} = require('child_process');
const {promisify} = require('util');
const exec = promisify(execFile);
const binary = process.env.VAUTH_TEST_BINARY;
const command = binary ? [binary] : [process.execPath, path.resolve(__dirname, '../cmd/vauth.js')];

async function fixture(t, rc, handler) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'vvauth-source-'));
  t.after(() => fs.rmSync(home, {recursive : true, force : true}));
  const file = path.join(home, '.vauthrc');
  const bin = path.join(home, 'bin');
  fs.mkdirSync(bin);
  fs.symlinkSync(binary || command[1], path.join(bin, 'vauth'));
  // Only synthetic credentials/configuration reach either CLI, never the user's environment.
  const env = {PATH : `${bin}:${process.env.PATH}`, HOME : home, USERPROFILE : home, VAUTHRC : file};
  if(handler) {
    const server = http.createServer(handler);
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    env.VAULT_ADDR = `http://127.0.0.1:${server.address().port}`;
    rc.vault_addr = env.VAULT_ADDR;
    rc.token_cache = false;
  }
  fs.writeFileSync(file, typeof rc === 'string' ? rc : JSON.stringify(rc));
  const run = async (program, args) => {
    try {
      return {...await exec(program, args, {cwd : home, env}), code : 0};
    } catch(err) {
      return err;
    }
  };
  return {
    env,
    cli : (...args) => run(command[0], [...command.slice(1), ...args]),
    shell : (script, ...args) => run('bash', ['--noprofile', '--norc', '-c', script, '_', ...args]),
  };
}

const failureShell = `
function venv() { source <(/usr/bin/env vauth env --source "$@"); }
OK=caller
unset BAD
initial_token=\${VAULT_TOKEN-unset}
venv
status=$?
if [ "\${VAULT_TOKEN-unset}" = "$initial_token" ]; then token=unchanged; else token=changed; fi
printf '%s|continued|%s|%s|%s\\n' "$status" "$OK" "\${BAD-unset}" "$token"
`;
const map = {OK : 'synthetic-secret', BAD : '$${delegate.unknown}'};
const cases = [
  ['malformed configuration', 'env: [\n', /parse|YAML|flow|end/i],
  ['invalid delegation configuration', {delegate : {}, env : {map}}, /Invalid Vault delegation/],
  ['invalid variable name', {env : {map : {OK : 'synthetic-secret', 'BAD-NAME' : 'value'}}}, /Invalid environment variable name/],
  ['invalid map value', {env : {map : {OK : 'synthetic-secret', BAD : {nested : true}}}}, /Invalid environment value/],
  ['unknown macro', {env : {map}}, /Unknown Vault delegation/],
  ['missing GitLab prerequisite', {env : {gitlab : true, map}}, /Missing CI_PROJECT/],
  ['missing local secret file', {'ssh-agent-crypt' : {path : 'missing-synthetic-file'}, env : {map}}, /no such file|ENOENT/i],
  ['authentication denied', {jwt_auth : {role : 'synthetic-role', jwt : 'synthetic-jwt'}, env : {map}}, /403/,
    (req, res) => { res.writeHead(403); res.end('{"errors":["synthetic-denied"]}'); }],
  ['profile denied', {env : {map}}, /403/, (req, res) => {
    if(req.url.endsWith('/auth/token/lookup-self')) {
      res.end(JSON.stringify({data : {entity_id : 'synthetic-entity', ttl : 3600}}));
    } else {
      res.writeHead(403); res.end('{"errors":["synthetic-denied"]}');
    }
  }],
  ['secret path denied', {env : {paths : ['synthetic-path'], map}}, /403/, (req, res) => {
    if(req.url.endsWith('/auth/token/lookup-self')) {
      res.end(JSON.stringify({data : {entity_id : 'synthetic-entity', ttl : 3600}}));
    } else if(req.url.includes('/identity/entity/id/')) {
      res.end('{"data":{"metadata":{}}}');
    } else {
      res.writeHead(403); res.end('{"errors":["synthetic-denied"]}');
    }
  }],
];

for(const [name, rc, diagnostic, handler] of cases) {
  test(`${binary ? 'Go' : 'Node'} env --source: ${name}`, async t => {
    const f = await fixture(t, rc, handler);
    if(['profile denied', 'secret path denied'].includes(name))
      f.env.VAULT_TOKEN = 'synthetic-parent';
    const result = await f.cli('env', '--source');
    assert.equal(result.code, 1);
    assert.equal(result.stdout, 'return 1\n');
    assert.match(result.stderr, diagnostic);
    assert.ok(!result.stderr.includes('synthetic-secret'));
    assert.ok(!result.stderr.includes('synthetic-parent'));
    const shell = await f.shell(failureShell);
    assert.equal(shell.code, 0);
    assert.equal(shell.stdout, '1|continued|caller|unset|unchanged\n');
    assert.match(shell.stderr, diagnostic);
  });
}

test('non-source failures keep stdout empty', async t => {
  const f = await fixture(t, {env : {map}});
  for(const args of [['env', '--ir://json'], ['env', '--source=0', '--ir://json']]) {
    const result = await f.cli(...args);
    assert.equal(result.code, 1);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /Unknown Vault delegation/);
  }
});

test('successful exports, JSON and source flags are unchanged', async t => {
  const values = {OK : "spaces ' quotes\nnew line", COUNT : 42, FLAG : false, EMPTY : null};
  const f = await fixture(t, {env : {map : values}});
  const exports = {
    OK : `export OK='spaces '"'"' quotes\nnew line'\necho export OK="[redacted]" >&2\n`,
    COUNT : `export COUNT='42'\necho export COUNT="[redacted]" >&2\n`,
    FLAG : `export FLAG='false'\necho export FLAG="[redacted]" >&2\n`,
    EMPTY : `export EMPTY=''\necho export EMPTY="[redacted]" >&2\n`,
  };
  // Go's configuration clone already sorts map keys; Node retains insertion order.
  const keys = binary ? Object.keys(values).sort() : Object.keys(values);
  const expected = keys.map(key => exports[key]).join('');
  for(const flags of [['--source'], ['--source', '--renew'], ['--source', '--renew=0'],
    ['--source', '--ir://json'], ['--source=1']]) {
    const result = await f.cli('env', ...flags);
    assert.equal(result.code, 0);
    assert.equal(result.stdout, expected);
  }
  const json = await f.cli('env', '--ir://json');
  assert.equal(json.code, 0);
  assert.deepEqual(JSON.parse(json.stdout), {...values, COUNT : '42', FLAG : 'false', EMPTY : ''});
  const shell = await f.shell(`
function venv() { source <(/usr/bin/env vauth env --source "$@"); }
venv "$@"
status=$?
printf '%s|continued|%s|%s|%s|%s\\n' "$status" "$OK" "$COUNT" "$FLAG" "$EMPTY"
`, '--renew=0');
  assert.equal(shell.code, 0);
  assert.equal(shell.stdout, `0|continued|${values.OK}|42|false|\n`);
});

test('renew flag still forces login instead of the inherited token', async t => {
  let logins = 0;
  const f = await fixture(t, {jwt_auth : {role : 'synthetic-role', jwt : 'synthetic-jwt'}}, (req, res) => {
    if(req.url.endsWith('/auth/jwt/login')) {
      logins++;
      res.end('{"auth":{"client_token":"synthetic-issued","lease_duration":3600,"renewable":false}}');
    } else if(req.url.endsWith('/auth/token/lookup-self')) {
      res.end('{"data":{"entity_id":"synthetic-entity","ttl":3600}}');
    } else {
      res.end('{"data":{"metadata":{}}}');
    }
  });
  f.env.VAULT_TOKEN = 'synthetic-parent';
  const reused = await f.cli('env', '--source', '--renew=0');
  assert.equal(reused.code, 0);
  assert.match(reused.stdout, /export VAULT_TOKEN='synthetic-parent'/);
  assert.equal(logins, 0);
  const renewed = await f.cli('env', '--source', '--renew');
  assert.equal(renewed.code, 0);
  assert.match(renewed.stdout, /export VAULT_TOKEN='synthetic-issued'/);
  assert.equal(logins, 1);
});
