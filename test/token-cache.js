'use strict';

const assert = require('node:assert/strict');
const {test, before, after} = require('node:test');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const {execFile, spawn, spawnSync} = require('child_process');
const {promisify, format} = require('util');
const exec = promisify(execFile);
const Vauth = require('../index');

const {encrypt, decrypt} = require('ssh-agent-crypt');
const readCache = async file => JSON.parse(await decrypt(fs.readFileSync(file, 'utf8')));
const writeCache = async (file, cache) => fs.writeFileSync(file, await encrypt(JSON.stringify(cache)));
let agentDirectory, agentPid;
const previousSocket = process.env.SSH_AUTH_SOCK;
const previousIdentity = process.env.VAUTH_USER_IDENTITY;
const previousMail = process.env.VAUTH_USER_MAIL;
const previousCryptKey = process.env.SSH_AGENT_CRYPT_KEY;

before(() => {
  delete process.env.VAUTH_USER_IDENTITY;
  delete process.env.VAUTH_USER_MAIL;
  delete process.env.SSH_AGENT_CRYPT_KEY;
  agentDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'vvauth-agent-'));
  const key = path.join(agentDirectory, 'key');
  assert.equal(spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', key]).status, 0);
  const agent = spawnSync('ssh-agent', ['-s'], {encoding : 'utf8'});
  assert.equal(agent.status, 0);
  process.env.SSH_AUTH_SOCK = agent.stdout.match(/SSH_AUTH_SOCK=([^;]+)/)[1];
  agentPid = agent.stdout.match(/SSH_AGENT_PID=(\d+)/)[1];
  assert.equal(spawnSync('ssh-add', [key]).status, 0);
});

after(() => {
  for(const [name, value] of [['VAUTH_USER_IDENTITY', previousIdentity], ['VAUTH_USER_MAIL', previousMail], ['SSH_AGENT_CRYPT_KEY', previousCryptKey]]) {
    if(value === undefined)
      delete process.env[name];
    else
      process.env[name] = value;
  }
  if(agentPid)
    process.kill(Number(agentPid));
  if(previousSocket === undefined)
    delete process.env.SSH_AUTH_SOCK;
  else
    process.env.SSH_AUTH_SOCK = previousSocket;
  fs.rmSync(agentDirectory, {recursive : true, force : true});
});

const HOUR = 60 * 60;

// Exercise real construction under an isolated RC, without changing private data.
function configuredClient(t, document, overrides = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'vvauth-config-'));
  t.after(() => fs.rmSync(home, {recursive : true, force : true}));
  const file = path.join(home, '.vauthrc');
  fs.writeFileSync(file, JSON.stringify(document));
  const env = {HOME : home, USERPROFILE : home, VAUTHRC : file, VAULT_TOKEN : '', VAULT_ADDR : '', ...overrides};
  const previous = {};
  for(const key of Object.keys(env)) { previous[key] = process.env[key]; process.env[key] = env[key]; }
  const modules = [require.resolve('../index'), require.resolve('vauth-login')];
  const cached = modules.map(file => require.cache[file]);
  for(const file of modules) delete require.cache[file];
  try { return new (require('../index'))(); } finally {
    modules.forEach((file, i) => { require.cache[file] = cached[i]; });
    for(const key of Object.keys(env)) {
      if(previous[key] === undefined) delete process.env[key];
      else process.env[key] = previous[key];
    }
  }
}

async function fixture(t, options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vvauth-test-'));
  let file;
  const requests = [];
  let database = options.database || {};
  const server = http.createServer(async (req, res) => {
    let body = '';
    for await(const chunk of req)
      body += chunk;
    requests.push({path : req.url, method : req.method, token : req.headers['x-vault-token'], body});
    res.setHeader('content-type', 'application/json');
    if(req.url === '/v1/auth/jwt/login') {
      res.end(JSON.stringify({auth : {client_token : 'fresh-token', lease_duration : 24 * HOUR, renewable : true}}));
    } else if(req.url === '/v1/auth/token/lookup-self') {
      res.statusCode = options.lookup_status || 200;
      res.end(JSON.stringify({data : {ttl : options.ttl === undefined ? 12 * HOUR : options.ttl, renewable : options.renewable !== false, creation_ttl : options.creation_ttl === undefined ? 24 * HOUR : options.creation_ttl, entity_id : 'test-entity'}}));
    } else if(req.url === '/v1/auth/token/renew-self') {
      res.statusCode = options.renew_status || 200;
      res.end(JSON.stringify({auth : {client_token : req.headers['x-vault-token'], lease_duration : 24 * HOUR, renewable : true}}));
    } else if(req.url === '/v1/identity/entity/id/test-entity') {
      res.end(JSON.stringify({data : {metadata : options.metadata || {}}}));
    } else if(req.url === '/v1/private/alice/data/.vauth_database') {
      if(req.method === 'POST') database = JSON.parse(body).data;
      res.end(JSON.stringify({data : {data : database}}));
    } else if(req.url === '/v1/secrets/data/app') {
      res.end(JSON.stringify({data : {data : options.secrets || {}}}));
    } else {
      res.statusCode = 404;
      res.end('{}');
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(directory, {recursive : true, force : true});
  });
  const client = (settings = {}) => {
    const rc = {vault_addr : `http://127.0.0.1:${server.address().port}`, jwt_auth : {path : 'jwt', jwt : 'test-jwt', role : 'test-role'}, ...settings.rc};
    if(settings.noAuth) delete rc.jwt_auth;
    const instance = configuredClient(t, rc, {VAULT_TOKEN : settings.token || '', ...settings.env});
    instance._token_cache_file = () => path.join(directory, '.vauth', 'tokens', instance._token_cache_key() + '.creds');
    return instance;
  };
  file = client()._token_cache_file();
  const remaining = async (instance, ttl) => {
    const file = instance._token_cache_file();
    const cache = (await readCache(file));
    cache.expires_at = ttl === 0 ? null : Date.now() + ttl * 1000;
    await writeCache(file, cache);
  };
  const seed = async (instance, lease = 12 * HOUR) => {
    await instance._save_cached_token('cached-token', {lease_duration : lease, renewable : options.renewable !== false});
    if(options.ttl !== undefined)
      await remaining(instance, options.ttl);
  };
  const read = async instance => readCache(instance._token_cache_file());
  return {client, seed, read, requests, file, remaining, database : () => database};
}

test('login persists a token; a new instance reuses it without logging in', async t => {
  const {client, read, requests, file} = await fixture(t);
  const first = client();
  assert.equal(await first.Connect(), 'fresh-token');
  assert.equal((await read(first)).token, 'fresh-token');
  assert.ok((await read(first)).expires_at > Date.now() + 23 * HOUR * 1000);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
  const second = client();
  assert.equal(await second.Connect(), 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
  assert.deepEqual(fs.readdirSync(path.dirname(file)), [path.basename(file)]);
});

test('a token in the last third of its lease is renewed and saved', async t => {
  const {client, seed, read, requests} = await fixture(t, {ttl : HOUR});
  const instance = client();
  await seed(instance, 12 * HOUR);
  assert.equal(await instance.Connect(), 'cached-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/token/renew-self']);
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].token, 'cached-token');
  assert.ok((await read(instance)).expires_at > Date.now() + 23 * HOUR * 1000);
});

test('more than one third remaining does not trigger renewal', async t => {
  const {client, seed, requests} = await fixture(t, {ttl : 4 * HOUR + 1});
  const instance = client();
  await seed(instance);
  assert.equal(await instance.Connect(), 'cached-token');
  assert.equal(requests.length, 0);
});

test('expired cached tokens are replaced with a new persisted login', async t => {
  const {client, seed, read, requests, file} = await fixture(t);
  const instance = client();
  await seed(instance);
  const cache = (await readCache(file));
  cache.expires_at = Date.now() - 1000;
  await writeCache(file, cache);
  assert.equal(await instance.Connect(), 'fresh-token');
  assert.equal((await read(instance)).token, 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
});

test('cached tokens are reused without checking revocation', async t => {
  const {client, seed, requests} = await fixture(t, {lookup_status : 403});
  const instance = client();
  await seed(instance);
  assert.equal(await instance.Connect(), 'cached-token');
  assert.deepEqual(requests, []);
  await assert.rejects(instance.LookupSelf(instance.VAULT_TOKEN));
});

test('nonrenewable tokens nearing expiry trigger reauthentication', async t => {
  const {client, seed, requests} = await fixture(t, {ttl : HOUR, renewable : false});
  const instance = client();
  await seed(instance);
  assert.equal(await instance.Connect(), 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
});

for(const status of [400, 403]) {
  test(`rejected renewal (${status}) triggers a new persisted login`, async t => {
    const {client, seed, read, requests} = await fixture(t, {ttl : HOUR, renew_status : status});
    const instance = client();
    await seed(instance);
    assert.equal(await instance.Connect(), 'fresh-token');
    assert.equal((await read(instance)).token, 'fresh-token');
    assert.deepEqual(requests.map(req => req.path), ['/v1/auth/token/renew-self', '/v1/auth/jwt/login']);
  });
}

test('server failures do not generate extra tokens, and connect can be retried', async t => {
  const {client, seed, requests} = await fixture(t, {lookup_status : 500});
  const instance = client({token : 'uncached-token'});
  await seed(instance);
  assert.equal(await instance.Connect(), 'uncached-token');
  await assert.rejects(instance.LookupSelf());
  await assert.rejects(instance.LookupSelf());
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/token/lookup-self', '/v1/auth/token/lookup-self']);
});

test('renewal server failures do not generate extra tokens', async t => {
  const {client, seed, requests} = await fixture(t, {ttl : HOUR, renew_status : 500});
  const instance = client();
  await seed(instance);
  await assert.rejects(instance.Connect());
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/token/renew-self']);
});

test('inherited tokens are returned offline without changing the cache', async t => {
  const {client, seed, read, requests} = await fixture(t);
  const instance = client({token : 'environment-token'});
  await seed(instance);
  assert.equal(await instance.Connect(), 'environment-token');
  assert.equal((await read(instance)).token, 'cached-token');
  assert.deepEqual(requests, []);
});

test('nonexpiring tokens are reused without renewal', async t => {
  const {client, seed, read, requests} = await fixture(t, {ttl : 0});
  const instance = client();
  await seed(instance, 0);
  assert.equal(await instance.Connect(), 'cached-token');
  assert.equal((await read(instance)).expires_at, null);
  assert.equal(requests.length, 0);
});

test('corrupt caches are replaced with a valid cache', async t => {
  const {client, read, file} = await fixture(t);
  fs.mkdirSync(path.dirname(file), {recursive : true});
  fs.writeFileSync(file, '{broken');
  const instance = client();
  assert.equal(await instance.Connect(), 'fresh-token');
  assert.equal((await read(instance)).token, 'fresh-token');
});

test('cache entries are isolated by Vault address and authentication configuration', async t => {
  const {client, seed, read, file} = await fixture(t);
  const first = client();
  await seed(first);
  const second = client({rc : {jwt_auth : {path : 'jwt', jwt : 'test-jwt', role : 'other-role'}}});
  assert.equal(await second.Connect(), 'fresh-token');
  assert.notEqual(first._token_cache_file(), second._token_cache_file());
  assert.equal((await read(first)).token, 'cached-token');
  assert.equal((await read(second)).token, 'fresh-token');
  const third = client({rc : {vault_addr : 'http://other-vault.test'}});
  assert.notEqual(third._token_cache_key(), first._token_cache_key());
  assert.equal(fs.readdirSync(path.dirname(file)).length, 2);
  assert.ok(!fs.readFileSync(file, 'utf8').includes('test-jwt'));
});

test('repeated connect calls reuse the established connection', async t => {
  const {client, requests} = await fixture(t);
  const instance = client();
  assert.equal(await instance.Connect(), 'fresh-token');
  assert.equal(await instance.Connect(), 'fresh-token');
  assert.equal(requests.length, 1);
});

test('an unwritable cache does not prevent login', async t => {
  const {client, file} = await fixture(t);
  fs.mkdirSync(path.dirname(path.dirname(file)), {recursive : true});
  fs.writeFileSync(path.dirname(file), 'not a directory');
  assert.equal(await client().Connect(), 'fresh-token');
});

test('without an auth method inherited tokens are returned but caches are ignored', async t => {
  const {client, seed} = await fixture(t, {lookup_status : 403});
  const instance = client({token : 'uncached-token', noAuth : true});
  await seed(instance);
  instance._read_token_cache = async () => { throw new Error('No auth: no cache lookup'); };
  assert.equal(await instance.Connect(), 'uncached-token');
  assert.equal(instance.VAULT_TOKEN, 'uncached-token');
});

test('--renew ignores both environment and cached tokens and saves a new token', async t => {
  const {client, seed, read, requests} = await fixture(t);
  const instance = client({token : 'environment-token'});
  await seed(instance);
  assert.equal(await instance.Connect(true), 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
  assert.equal((await read(instance)).token, 'fresh-token');
  assert.ok((await read(instance)).expires_at > Date.now() + 23 * HOUR * 1000);
});

test('--renew replaces the token of a previously connected instance', async t => {
  const {client, seed, read, requests} = await fixture(t);
  const instance = client();
  await seed(instance);
  await instance.Connect();
  assert.equal(await instance.Connect(true), 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
  assert.equal((await read(instance)).token, 'fresh-token');
});

test('each successive --renew call forces a new login', async t => {
  const {client, requests} = await fixture(t);
  const instance = client();
  assert.equal(await instance.Connect(true), 'fresh-token');
  assert.equal(await instance.Connect(true), 'fresh-token');
  assert.equal(requests.length, 2);
});

test('--renew without an authentication method remains a no-op', async t => {
  const {client} = await fixture(t);
  const instance = client({noAuth : true});
  assert.equal(await instance.Connect(true), undefined);
});

for(const flag of ['renew']) {
  test(`env forwards --${flag} into forced reauthentication`, async t => {
    const {client} = await fixture(t);
    const instance = client();
    let forced;
    instance.Connect = async renew => { forced = renew; };
    assert.deepEqual(await instance.Env(false, true), {VAULT_ADDR : instance.VAULT_ADDR});
    assert.equal(forced, true);
  });

  for(const command of ['env', 'login']) {
    test(`real CLI ${command} --${flag} generates and caches a new token`, async t => {
      const {client, seed, read, requests, file} = await fixture(t);
      const instance = client();
      await seed(instance);
      const home = path.dirname(path.dirname(path.dirname(file)));
      const rc = path.join(home, '.vauthrc');
      fs.writeFileSync(rc, JSON.stringify({vault_addr : instance.VAULT_ADDR, ...instance.RC}));
      const options = {
        cwd : home,
        env : {...process.env, HOME : home, VAUTHRC : rc, VAULT_TOKEN : 'environment-token', SSH_AUTH_SOCK : process.env.SSH_AUTH_SOCK},
      };
      const cli = path.resolve(__dirname, '..', 'cmd', 'vauth.js');
      const output = await exec(process.execPath, [cli, command, '--source', `--${flag}`], options);
      assert.ok(output.stdout.includes("export VAULT_TOKEN='fresh-token'"));
      assert.ok(!output.stdout.includes('Vauth token: '));
      assert.equal(output.stderr.split('\n').filter(line => line === `Vauth token: generated · 1d`).length, 1);
      assert.ok(!output.stderr.includes('Vauth token: renewed'));
      assert.ok(!output.stderr.includes('fresh-token'));
      assert.ok(!output.stderr.includes('environment-token'));
      assert.deepEqual(requests.filter(req => !req.path.startsWith('/v1/identity/')).map(req => req.path), command === 'env'
        ? ['/v1/auth/jwt/login', '/v1/auth/token/lookup-self'] : ['/v1/auth/jwt/login']);
      assert.equal((await read(instance)).token, 'fresh-token');
      assert.equal(fs.statSync(file).mode & 0o777, 0o600);
      requests.length = 0;
      const reused = await exec(process.execPath, [cli, command, '--source'], {
        ...options, env : {...options.env, VAULT_TOKEN : ''},
      });
      assert.ok(reused.stdout.includes("export VAULT_TOKEN='fresh-token'"));
      assert.equal(reused.stderr.split('\n').filter(line => line.startsWith('Vauth token: ')).length, 1);
      assert.ok(reused.stderr.includes(`Vauth token: reused · 1d`));
      assert.ok(!requests.some(req => req.path.endsWith('/login') || req.path.endsWith('/renew-self')));
    });
  }
}

test('installed venv forwards --renew through the real CLI', async t => {
  const {client, seed, read, requests, file} = await fixture(t);
  const instance = client();
  await seed(instance);
  const home = path.dirname(path.dirname(path.dirname(file)));
  const original_home = os.homedir;
  instance._function_exists = async () => 1;
  try {
    os.homedir = () => home;
    await instance.Install();
  } finally {
    os.homedir = original_home;
  }
  const declaration = fs.readFileSync(path.join(home, '.bashrc'), 'utf8');
  assert.ok(declaration.includes('vauth env --source "$@"'));
  const bin = path.join(home, 'bin');
  fs.mkdirSync(bin);
  fs.symlinkSync(path.resolve(__dirname, '..', 'cmd', 'vauth.js'), path.join(bin, 'vauth'));
  const rc = path.join(home, '.vauthrc');
  fs.writeFileSync(rc, JSON.stringify({vault_addr : instance.VAULT_ADDR, ...instance.RC}));
  const options = {
    cwd : home,
    env : {...process.env, HOME : home, VAUTHRC : rc, VAULT_TOKEN : '', SSH_AUTH_SOCK : process.env.SSH_AUTH_SOCK, PATH : `${bin}:${process.env.PATH}`},
  };
  const initial = await exec('bash', ['-c', `${declaration}\nvenv; printf '%s' "$VAULT_TOKEN"`], options);
  assert.equal(initial.stdout, 'cached-token');
  assert.equal(initial.stderr.split('\n').filter(line => line.startsWith('Vauth token: ')).length, 1);
  assert.ok(initial.stderr.includes(`Vauth token: reused · 12h`));
  assert.ok(!requests.some(req => req.path.endsWith('/login') || req.path.endsWith('/renew-self')));
  for(const flag of ['--renew']) {
    const output = await exec('bash', ['-c', `${declaration}\nvenv ${flag}; printf '%s' "$VAULT_TOKEN"`], options);
    assert.equal(output.stdout, 'fresh-token');
    assert.equal(output.stderr.split('\n').filter(line => line === `Vauth token: generated · 1d`).length, 1);
    assert.ok(!output.stderr.includes('Vauth token: renewed'));
    assert.ok(!output.stderr.includes('fresh-token'));
    assert.equal((await read(instance)).token, 'fresh-token');
  }
  assert.equal(requests.filter(req => req.path.endsWith('/login')).length, 1);
  assert.ok(!requests.some(req => req.path.endsWith('/renew-self')));
});

for(const answer of ['yes', 'no', '']) {
  test(`install asks before overriding an existing function: ${JSON.stringify(answer)}`, async t => {
    const {file} = await fixture(t);
    const home = path.dirname(path.dirname(path.dirname(file)));
    const bashrc = path.join(home, '.bashrc');
    const original = '# before\nfunction venv() { source <(/usr/bin/env vauth env --source); }\n# after\n';
    fs.writeFileSync(bashrc, original);
    const module_path = path.resolve(__dirname, '..', 'index.js');
    const script = `const Vauth = require(${JSON.stringify(module_path)});
      const instance = Object.create(Vauth.prototype);
      instance._function_exists = async () => 0;
      instance.Install().catch(() => process.exit(1));`;
    const child = spawn(process.execPath, ['-e', script], {cwd : home, env : {...process.env, HOME : home}});
    let output = '', prompted = false;
    child.stdout.on('data', chunk => {
      output += chunk;
      if(!prompted && output.includes('[y/N]')) {
        prompted = true;
        child.stdin.end(answer + '\n');
      }
    });
    child.stderr.resume();
    const exit = await new Promise((resolve, reject) => {
      child.on('error', reject);
      child.on('exit', resolve);
    });
    assert.equal(exit, 0);
    assert.ok(output.includes('Function already defined, override current definition?'));
    const declaration = 'function venv() { source <(/usr/bin/env vauth env --source "$@"); }\n';
    assert.equal(fs.readFileSync(bashrc, 'utf8'), answer === 'yes' ? original + declaration : original);
  });
}

function captureStatus(callback) {
  const lines = [];
  const original = console.error;
  console.error = (...args) => lines.push(format(...args));
  try {
    callback();
  } finally {
    console.error = original;
  }
  return lines;
}

test('token status uses humanDiff with two significant units', () => {
  const instance = Object.create(Vauth.prototype);
  const cases = [
    [2 * 86400 + 3 * HOUR + 20 * 60 + 5, '2d 3h'],
    [12 * HOUR + 30 * 60 + 5, '12h 30m'],
    [5 * 60 + 20, '5m 20s'],
    [86400, '1d'],
    [30 * 60, '30m'],
    [45, '45s'],
    [86400 + 20, '1d 20s'],
    [HOUR + 5, '1h 5s'],
    [400 * 86400 + 2 * HOUR, '1y 1month'],
    [60.9, '1m 1s'],
  ];
  for(const [ttl, duration] of cases) {
    assert.deepEqual(captureStatus(() => instance._token_status('reused', {ttl})), [
      `Vauth token: reused · ${duration}`,
    ]);
  }
  assert.deepEqual(captureStatus(() => instance._token_status('renewed', {lease_duration : HOUR + 60})), [
    `Vauth token: renewed · 1h 1m`,
  ]);
  assert.deepEqual(captureStatus(() => instance._token_status('generated', {lease_duration : 0})), [
    `Vauth token: generated · valid indefinitely`,
  ]);
});

for(const options of [
  {ttl : 12 * HOUR, operation : 'reused', duration : '12h'},
  {ttl : HOUR, operation : 'renewed', duration : '1d'},
  {ttl : HOUR, renew_status : 400, operation : 'generated', duration : '1d'},
  {ttl : HOUR, renew_status : 403, operation : 'generated', duration : '1d'},
  {ttl : 0, operation : 'reused', duration : null},
]) {
  test(`one final status per connection: ${JSON.stringify(options)}`, async t => {
    const {client, seed} = await fixture(t, options);
    const instance = client();
    await seed(instance);
    const calls = [];
    instance._token_status = (operation, metadata) => {
      calls.push(...captureStatus(() => Vauth.prototype._token_status.call(instance, operation, metadata)));
    };
    await instance.Connect();
    await instance.Connect();
    const validity = options.duration ? `valid for ${options.duration}` : 'valid indefinitely';
    assert.deepEqual(calls, [`Vauth token: ${options.operation} · ${validity.replace(/^valid for /, '')}`]);
  });
}

test('failed connections never announce successful token status', async t => {
  const {client, seed} = await fixture(t, {ttl : HOUR, renew_status : 500});
  const instance = client();
  await seed(instance);
  const calls = [];
  instance._token_status = operation => calls.push(operation);
  await assert.rejects(instance.Connect());
  assert.deepEqual(calls, []);
});

for(const [lease, remaining, renew] of [
  [24 * HOUR, 8 * HOUR, true],
  [24 * HOUR, 8 * HOUR + 1, false],
  [HOUR, 20 * 60, true],
  [HOUR, 20 * 60 + 1, false],
  [60, 20, true],
  [60, 21, false],
]) {
  test(`proportional threshold: lease=${lease}, remaining=${remaining}`, async t => {
    const {client, seed, read, requests} = await fixture(t, {ttl : remaining});
    const instance = client();
    await seed(instance, lease);
    await instance.Connect();
    assert.equal(requests.some(req => req.path.endsWith('/renew-self')), renew);
    assert.equal((await read(instance)).lease_duration, renew ? 24 * HOUR : lease);
  });
}

test('lookups never reset the original lease duration', async t => {
  const options = {ttl : 20 * HOUR};
  const {client, seed, read, requests, remaining} = await fixture(t, options);
  const instance = client();
  await seed(instance, 24 * HOUR);
  await instance.Connect();
  assert.equal((await read(instance)).lease_duration, 24 * HOUR);
  await remaining(instance, 12 * HOUR);
  await client().Connect();
  assert.equal((await read(instance)).lease_duration, 24 * HOUR);
  await remaining(instance, 8 * HOUR);
  await client().Connect();
  assert.equal(requests.filter(req => req.path.endsWith('/renew-self')).length, 1);
});

test('renewal updates the lease baseline to the newly granted duration', async t => {
  const options = {ttl : 20 * 60};
  const {client, seed, read, requests, remaining} = await fixture(t, options);
  const instance = client();
  await seed(instance, HOUR);
  await instance.Connect();
  assert.equal((await read(instance)).lease_duration, 24 * HOUR);
  await remaining(instance, 8 * HOUR);
  await client().Connect();
  assert.equal(requests.filter(req => req.path.endsWith('/renew-self')).length, 2);
});

test('normal reuse never writes the token cache', async t => {
  const {client, seed, file, requests} = await fixture(t);
  const instance = client({token : 'cached-token'});
  await seed(instance);
  const before = fs.readFileSync(file, 'utf8');
  const stat = fs.statSync(file);
  instance._save_cached_token = () => { throw new Error('Reuse must not write'); };
  assert.equal(await instance.Connect(), 'cached-token');
  assert.equal(fs.readFileSync(file, 'utf8'), before);
  assert.equal(fs.statSync(file).ino, stat.ino);
  assert.equal(fs.statSync(file).mtimeMs, stat.mtimeMs);
  assert.deepEqual(requests, []);
});


test('lookup returns the lease duration and preserves a cached renewal baseline', async t => {
  const {client, seed, requests} = await fixture(t, {ttl : HOUR, creation_ttl : 24 * HOUR});
  const instance = client();
  const uncached = await instance.LookupSelf('environment-token');
  assert.equal(uncached.lease_duration, 24 * HOUR);
  assert.equal(uncached.ttl, HOUR);
  await seed(instance, 12 * HOUR);
  const cached = await instance.LookupSelf('cached-token');
  assert.equal(cached.lease_duration, 12 * HOUR);
  assert.equal(requests.length, 2);
});

test('token_cache false skips all cache filesystem access', async t => {
  const {client, requests, file} = await fixture(t);
  const instance = client({rc : {token_cache : false}});
  instance._token_cache_file = () => { throw new Error('Disabled cache must not access disk'); };
  assert.equal(await instance.Connect(), 'fresh-token');
  assert.equal(fs.existsSync(file), false);
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
});

test('token_cache false ignores existing tokens on disk without deleting them', async t => {
  const {client, seed, requests, file} = await fixture(t);
  await seed(client());
  const instance = client({rc : {token_cache : false}});
  const before = fs.readFileSync(file, 'utf8');
  assert.equal(await instance.Connect(), 'fresh-token');
  assert.equal(fs.readFileSync(file, 'utf8'), before);
  const second = client({rc : {token_cache : false}});
  assert.equal(await second.Connect(), 'fresh-token');
  assert.equal(requests.filter(req => req.path.endsWith('/login')).length, 2);
});

test('token_cache false still respects an environment token without persisting it', async t => {
  const {client, requests, file} = await fixture(t);
  const instance = client({token : 'environment-token', rc : {token_cache : false}});
  assert.equal(await instance.Connect(), 'environment-token');
  assert.deepEqual(requests, []);
  assert.equal(fs.existsSync(file), false);
});

test('real CLI reads token_cache false from .vauthrc', async t => {
  const {client, file, requests} = await fixture(t);
  const instance = client();
  const home = path.dirname(path.dirname(path.dirname(file)));
  const rc = path.join(home, '.vauthrc');
  fs.writeFileSync(rc, JSON.stringify({vault_addr : instance.VAULT_ADDR, ...instance.RC, token_cache : false}));
  const cli = path.resolve(__dirname, '..', 'cmd', 'vauth.js');
  for(let i = 0; i < 2; i++) {
    const output = await exec(process.execPath, [cli, 'login', '--source'], {
      cwd : home,
      env : {...process.env, HOME : home, VAUTHRC : rc, VAULT_TOKEN : '', SSH_AUTH_SOCK : process.env.SSH_AUTH_SOCK},
    });
    assert.ok(output.stdout.includes("export VAULT_TOKEN='fresh-token'"));
    assert.ok(output.stderr.includes('Vauth token: generated'));
  }
  assert.equal(fs.existsSync(file), false);
  assert.equal(requests.filter(req => req.path.endsWith('/login')).length, 2);
});

test('disk cache contains only armor, interoperable with ssh-agent-crypt CLI', async t => {
  const {client, file} = await fixture(t);
  const instance = client();
  await instance.Connect();
  const armor = fs.readFileSync(file, 'utf8');
  assert.match(armor, /^ssh-agent-crypt:v3:/);
  assert.ok(!armor.includes('fresh-token'));
  assert.ok(!armor.includes('lease_duration'));
  assert.ok(!armor.includes('test-jwt'));
  const cli = require.resolve('ssh-agent-crypt/bin/ssh-agent-crypt');
  const decoded = spawnSync('bash', [cli, '-decrypt'], {input : armor, encoding : 'utf8'});
  assert.equal(decoded.status, 0);
  assert.equal(JSON.parse(decoded.stdout).token, 'fresh-token');
});

test('a plaintext cache is not accepted as a token cache', async t => {
  const {client, file, requests} = await fixture(t);
  const instance = client();
  fs.mkdirSync(path.dirname(file), {recursive : true});
  fs.writeFileSync(file, JSON.stringify({token : 'plaintext-token', lease_duration : 86400, expires_at : Date.now() + 86400000}));
  assert.equal(await instance.Connect(), 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
  assert.match(fs.readFileSync(file, 'utf8'), /^ssh-agent-crypt:v3:/);
});

test('without an SSH agent cache is skipped silently', async t => {
  const {client, file} = await fixture(t);
  const instance = client({env : {SSH_AUTH_SOCK : ''}});
  instance._token_cache_file = () => { throw new Error('No agent: no disk access'); };
  const socket = process.env.SSH_AUTH_SOCK;
  const original = console.error;
  const messages = [];
  try {
    delete process.env.SSH_AUTH_SOCK;
    console.error = (...args) => messages.push(format(...args));
    assert.equal(await instance.Connect(), 'fresh-token');
  } finally {
    process.env.SSH_AUTH_SOCK = socket;
    console.error = original;
  }
  assert.equal(fs.existsSync(file), false);
  assert.equal(fs.existsSync(file + '.next'), false);
  assert.ok(!messages.some(message => message.includes('token not persisted')));
  assert.ok(!messages.join('\n').includes('fresh-token'));
});

test('without an SSH agent existing armor is left untouched', async t => {
  const {client, seed, file} = await fixture(t);
  await seed(client());
  const instance = client({env : {SSH_AUTH_SOCK : ''}});
  const before = fs.readFileSync(file, 'utf8');
  const socket = process.env.SSH_AUTH_SOCK;
  try {
    delete process.env.SSH_AUTH_SOCK;
    await instance._save_cached_token('replacement-token', {lease_duration : 86400, renewable : true});
  } finally {
    process.env.SSH_AUTH_SOCK = socket;
  }
  assert.equal(fs.readFileSync(file, 'utf8'), before);
  assert.equal(fs.existsSync(file + '.next'), false);
});


test('constructor disables token caching when no SSH agent is configured', async t => {
  const {client, file} = await fixture(t);
  const instance = client();
  const home = path.dirname(path.dirname(path.dirname(file)));
  const rc = path.join(home, '.vauthrc');
  fs.writeFileSync(rc, JSON.stringify({vault_addr : instance.VAULT_ADDR, ...instance.RC, token_cache : true}));
  const module_path = path.resolve(__dirname, '..', 'index.js');
  const script = `const Vauth = require(${JSON.stringify(module_path)});
    const instance = new Vauth();
    let accesses = 0;
    instance._token_cache_file = () => { accesses++; throw new Error('Cache must be disabled'); };
    instance.Login().then(() => process.stdout.write(String(accesses))).catch(() => process.exit(1));`;
  const output = await exec(process.execPath, ['-e', script], {
    cwd : home,
    env : {...process.env, HOME : home, VAUTHRC : rc, VAULT_TOKEN : '', SSH_AUTH_SOCK : ''},
  });
  assert.equal(output.stdout.trim(), '0');
  assert.ok(!output.stderr.includes('token not persisted'));
  assert.equal(fs.existsSync(file), false);
});


for(const selected of ['identity', 'mail', 'default']) {
  test(`cache encryption selects ${selected}; decryption uses embedded fingerprint`, async t => {
    const {client, file} = await fixture(t);
    const instance = client();
    const directory = path.dirname(path.dirname(path.dirname(file)));
    const key = path.join(directory, 'selected-key');
    const comment = 'selected-cache@test';
    assert.equal(spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', comment, '-f', key]).status, 0);
    assert.equal(spawnSync('ssh-add', [key]).status, 0);
    try {
      if(selected === 'identity') {
        process.env.VAUTH_USER_IDENTITY = comment;
        process.env.VAUTH_USER_MAIL = 'missing-key@test';
      } else if(selected === 'mail') {
        process.env.VAUTH_USER_MAIL = comment;
      }
      assert.equal(await instance.Connect(), 'fresh-token');
      const fingerprint = spawnSync('ssh-keygen', ['-lf', key + '.pub'], {encoding : 'utf8'}).stdout.split(/\s+/)[1];
      const armor = fs.readFileSync(file, 'utf8');
      assert.equal(armor.startsWith(`ssh-agent-crypt:v3:${fingerprint}.`), selected !== 'default');
      delete process.env.VAUTH_USER_IDENTITY;
      delete process.env.VAUTH_USER_MAIL;
      assert.equal(await client().Connect(), 'fresh-token');
    } finally {
      spawnSync('ssh-add', ['-d', key]);
      delete process.env.VAUTH_USER_IDENTITY;
      delete process.env.VAUTH_USER_MAIL;
    }
  });
}

for(const explicit of [false, true]) {
  test(`.creds uses the JS module without a CLI (explicit identity=${explicit})`, async t => {
    const {client, file} = await fixture(t);
    const instance = client();
    const credentials = path.join(path.dirname(path.dirname(path.dirname(file))), '.creds');
    const identity = spawnSync('ssh-add', ['-l'], {encoding : 'utf8'}).stdout.split(/\s+/)[1];
    fs.writeFileSync(credentials, await encrypt(JSON.stringify({TEST_SECRET : 'module-secret'})));
    instance.config['ssh-agent-crypt'] = {path : credentials};
    if(explicit)
      instance.config['ssh-agent-crypt'].identity = identity;
    instance.config.env = {map : {EXPORTED_SECRET : '$${secrets.TEST_SECRET}'}};
    instance.GetProfile = async () => ({profile : {}, database : {}});
    const previousPath = process.env.PATH;
    try {
      process.env.PATH = path.dirname(credentials);
      const env = await instance.Env();
      assert.equal(env.EXPORTED_SECRET, 'module-secret');
    } finally {
      process.env.PATH = previousPath;
    }
  });
}

test('.creds decryption failures reject instead of exiting successfully', async t => {
  const {client, file} = await fixture(t);
  const instance = client();
  const credentials = path.join(path.dirname(path.dirname(path.dirname(file))), '.creds');
  fs.writeFileSync(credentials, 'not an armored payload');
  instance.config['ssh-agent-crypt'] = {path : credentials};
  instance.GetProfile = async () => ({profile : {}, database : {}});
  await assert.rejects(instance.Env(), /Unsupported format header/);
});

for(const inherited of ['', 'inherited-token']) {
  test(`local .creds environment works offline with inherited token=${!!inherited}`, async t => {
    const {client, file, requests} = await fixture(t, {lookup_status : 503});
    const instance = client({noAuth : true, token : inherited});
    const credentials = path.join(path.dirname(path.dirname(path.dirname(file))), '.creds');
    fs.writeFileSync(credentials, await encrypt(JSON.stringify({ARM_CLIENT_SECRET : 'local-secret', VAULT_TOKEN : 'local-token'})));
    instance.config = {
      'ssh-agent-crypt' : {path : credentials},
      env : {map : {ARM_CLIENT_SECRET : '$${secrets.ARM_CLIENT_SECRET}', VAULT_TOKEN : '$${secrets.VAULT_TOKEN}'}},
    };
    instance.LookupSelf = async () => { throw new Error('Local environment must not contact Vault'); };
    instance._read_token_cache = async () => { throw new Error('Local environment must not read the token cache'); };
    const env = await instance.Env();
    assert.equal(env.ARM_CLIENT_SECRET, 'local-secret');
    assert.equal(env.VAULT_TOKEN, 'local-token');
    assert.equal(env.VAULT_ADDR, instance.VAULT_ADDR);
    assert.deepEqual(requests, []);
  });
}

test('Windows keeps cache enabled and selects Pageant without SSH_AUTH_SOCK', async t => {
  const {client, file} = await fixture(t);
  const home = path.dirname(path.dirname(path.dirname(file)));
  const rc = path.join(home, 'foundry.vauthrc');
  fs.writeFileSync(rc, JSON.stringify({vault_addr : client().VAULT_ADDR, ssh_auth : {role : 'windows-role'}}));
  const module_path = path.resolve(__dirname, '..', 'index.js');
  const script = `const Vauth = require(${JSON.stringify(module_path)});
    Object.defineProperty(process, 'platform', {value: 'win32'});
    const instance = new Vauth();
    const result = {role: instance.RC.ssh_auth.role};
    let attempts = 0;
    instance._token_cache_file = () => { attempts++; return ${JSON.stringify(path.join(home, 'missing-cache'))}; };
    instance._save_cached_token = async () => {};
    instance._login_vault_ssh = async (auth, agent) => {
      result.agent = agent;
      return {client_token: 'windows-test-token', lease_duration: 86400, renewable: true};
    };
    instance._read_token_cache().then(() => {
      result.cacheDisabled = attempts === 0;
      instance._read_token_cache = async () => undefined;
      return instance.Connect();
    }).then(() => process.stdout.write(JSON.stringify(result))).catch(() => process.exit(1));`;
  const output = await exec(process.execPath, ['-e', script], {
    cwd : home,
    env : {...process.env, VAUTHRC : rc, VAULT_TOKEN : '', SSH_AUTH_SOCK : ''},
  });
  assert.deepEqual(JSON.parse(output.stdout), {cacheDisabled : false, role : 'windows-role', agent : 'pageant'});
});

test('env.map keys must be environment variable names (they reach `export KEY=` unescaped)', async t => {
  const {client} = await fixture(t);
  const instance = client();
  instance.config = {env : {map : {'SAFE; printf INJECTED >&2; #' : 'dummy'}}};
  await assert.rejects(instance.Env(), /Invalid environment variable name/);
  instance.config = {env : {map : {TF_HTTP_USERNAME : '$${profile.VAUTH_USER_LOGIN}'}}};
  assert.ok('TF_HTTP_USERNAME' in await instance.Env());
});

test('a project package.json may pin vvauth; other dependencies are ignored', async t => {
  const {version} = require('../package.json');
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'vvauth-project-'));
  t.after(() => fs.rmSync(cwd, {recursive : true, force : true}));
  const cli = path.resolve(__dirname, '..', 'cmd', 'vauth.js');
  const options = {cwd, env : {...process.env, HOME : cwd, VAUTHRC : path.join(cwd, 'none'), VAULT_ADDR : '', VAULT_TOKEN : '', SSH_AUTH_SOCK : ''}};

  fs.writeFileSync(path.join(cwd, 'package.json'), JSON.stringify({dependencies : {vvauth : `^${version}`, 'not-installed-anywhere' : '^9'}}));
  assert.equal(JSON.parse((await exec(process.execPath, [cli, 'version', '--ir://json'], options)).stdout), version);

  fs.writeFileSync(path.join(cwd, 'package.json'), JSON.stringify({dependencies : {vvauth : '<0.0.1'}}));
  await assert.rejects(exec(process.execPath, [cli, 'vauth:Connect', '--ir://json'], options), /Unsupported vvauth version .* \(project requires <0.0.1\)/);
});


test('profile, KV and environment use the inherited vauth-login transport', async t => {
  const Login = require('vauth-login');
  assert.equal(Object.getPrototypeOf(Vauth.prototype), Login.prototype);
  for(const name of ['LookupSelf', 'Request']) {
    assert.equal(Object.hasOwn(Vauth.prototype, name), false);
    assert.equal(Vauth.prototype[name], Login.prototype[name]);
  }
  const f = await fixture(t, {
    metadata : {VAUTH_USER_LOGIN : 'alice', VAUTH_USER_NAME : 'Alice', VAUTH_USER_MAIL : 'alice@example.test'},
    database : {TEAM : 'ops'}, secrets : {API_KEY : 'fixture-secret'},
  });
  const v = f.client();
  v.config.env = {map : {LOGIN : '$${profile.VAUTH_USER_LOGIN}', TEAM : '$${profile.TEAM}', API_KEY : '$${secrets.API_KEY}'}, paths : ['app'], git : true};
  const env = await v.Env(false, true);
  assert.equal(env.VAULT_TOKEN, 'fresh-token');
  assert.equal(env.LOGIN, 'alice');
  assert.equal(env.TEAM, 'ops');
  assert.equal(env.API_KEY, 'fixture-secret');
  assert.equal(env.GIT_AUTHOR_NAME, 'Alice');
  assert.deepEqual(f.requests.map(r => r.path), ['/v1/auth/jwt/login', '/v1/auth/token/lookup-self', '/v1/identity/entity/id/test-entity', '/v1/private/alice/data/.vauth_database', '/v1/secrets/data/app']);
  assert.ok(f.requests.slice(1).every(r => r.token === 'fresh-token'));
  await v.Set('feature', 'enabled');
  assert.equal(f.database().FEATURE, 'enabled');
  await v.Unset('feature');
  assert.equal(Object.hasOwn(f.database(), 'FEATURE'), false);
  assert.equal(f.requests.filter(r => r.path.endsWith('/login')).length, 1);
});

test('an unknown project Vault cannot receive inherited credentials through env or show', async t => {
  const f = await fixture(t);
  const home = path.dirname(path.dirname(path.dirname(f.file)));
  const project = path.join(home, 'project');
  fs.mkdirSync(project);
  fs.writeFileSync(path.join(project, '.vauthrc'), JSON.stringify({vault_addr : f.client().VAULT_ADDR, env : {map : {LOGIN : '$${profile.VAUTH_USER_LOGIN}'}}}));
  const options = {cwd : project, env : {...process.env, HOME : home, VAUTHRC : '', VAULT_ADDR : '', VAULT_TOKEN : 'inherited-token'}};
  const cli = path.resolve(__dirname, '..', 'cmd', 'vauth.js');
  assert.equal(JSON.parse((await exec(process.execPath, [cli, 'vauth:Connect', '--ir://json'], options)).stdout), 'inherited-token');
  for(const command of ['env', 'show']) {
    await assert.rejects(exec(process.execPath, [cli, command, '--ir://json'], options), err => {
      assert.equal(err.stdout, '');
      assert.match(err.stderr, /Unknown vault/);
      assert.ok(!err.stderr.includes('inherited-token'));
      return true;
    });
  }
  for(const args of [
    ['Request', '--method=GET', '--apiPath=identity/entity/id/test', '--token=inherited-token', '--ir://json'],
    ['LookupSelf', '--token=inherited-token', '--ir://json'],
  ]) {
    await assert.rejects(exec(process.execPath, [cli, ...args], options), err => {
      assert.equal(err.stdout, '');
      assert.match(err.stderr, /Unknown vault/);
      assert.ok(!err.stderr.includes('inherited-token'));
      return true;
    });
  }
  assert.deepEqual(f.requests, []);
});

test('constructor consumes one frozen RC snapshot without reopening the selected file', t => {
  const document = {env : {map : {VALUE : '$${env.LOCAL_VALUE}', USER : '$${profile.USER}'}}, extra : {nested : ['retained']}};
  const read = fs.readFileSync;
  let reads = 0;
  fs.readFileSync = function(file, ...args) {
    const body = read.call(this, file, ...args);
    if(file === process.env.VAUTHRC) {
      reads++;
      fs.unlinkSync(file);
    }
    return body;
  };
  let v;
  try {
    v = configuredClient(t, document, {LOCAL_VALUE : 'local-value', VAULT_ADDR : 'https://vault.example.test'});
  } finally {
    fs.readFileSync = read;
  }
  assert.equal(reads, 1);
  assert.deepEqual(v.RC, document);
  assert.equal(v.config.env.map.VALUE, 'local-value');
  assert.equal(v.config.env.map.USER, '$${profile.USER}');
  v.config.env.map.VALUE = 'consumer-value';
  assert.equal(v.RC.env.map.VALUE, '$${env.LOCAL_VALUE}');
  assert.ok(Object.isFrozen(v.RC.env.map));
  assert.equal(v.rc, undefined);
  assert.equal(v.rc_file, undefined);
});

test('env.gitlab no longer infers Git metadata in the constructor', async t => {
  const project = fs.mkdtempSync(path.join(os.tmpdir(), 'vvauth-git-project-'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'vvauth-git-config-'));
  t.after(() => fs.rmSync(project, {recursive : true, force : true}));
  t.after(() => fs.rmSync(home, {recursive : true, force : true}));
  assert.equal(spawnSync('git', ['init', '-q', project]).status, 0);
  assert.equal(spawnSync('git', ['-C', project, 'remote', 'add', 'origin', 'git@git.example.test:Team/app.git']).status, 0);
  const file = path.join(home, '.vauthrc');
  fs.writeFileSync(file, JSON.stringify({env : {gitlab : true, map : {PROJECT : '$${env.CI_PROJECT_PATH}'}}}));
  const script = `const V = require(${JSON.stringify(path.resolve(__dirname, '..', 'index.js'))}); process.stdout.write(JSON.stringify(new V().config));`;
  for(const CI of ['', '1']) {
    const {stdout} = await exec(process.execPath, ['-e', script], {
      cwd : project, env : {...process.env, HOME : home, VAUTHRC : file, VAULT_TOKEN : '', VAULT_ADDR : '', CI, CI_PROJECT_PATH : 'pipeline/project', CI_PROJECT_NAME : 'project', CI_PROJECT_NAMESPACE : 'pipeline', CI_PROJECT_PATH_SLUG : 'pipeline-project'},
    });
    assert.equal(JSON.parse(stdout).env.map.PROJECT, 'pipeline/project');
  }
});

test('gitlab publishes only CI exports without authentication or config writes', async t => {
  const project = fs.mkdtempSync(path.join(os.tmpdir(), 'vvauth-gitlab-'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'vvauth-gitlab-home-'));
  t.after(() => fs.rmSync(project, {recursive : true, force : true}));
  t.after(() => fs.rmSync(home, {recursive : true, force : true}));
  assert.equal(spawnSync('git', ['init', '-q', project]).status, 0);
  assert.equal(spawnSync('git', ['-C', project, 'remote', 'add', 'origin', 'ssh://git@git.example.test:2222/Team/sub/App.git']).status, 0);
  let requests = 0;
  const server = http.createServer((req, res) => { requests++; res.end('{}'); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const file = path.join(home, 'selected.vauthrc');
  const document = {vault_addr : `http://127.0.0.1:${server.address().port}`, jwt_auth : {jwt : 'fixture-jwt'}, env : {gitlab : true, map : {KEEP : 'literal'}}};
  const body = JSON.stringify(document);
  fs.writeFileSync(file, body);
  const env = {...process.env, HOME : home, VAUTHRC : file, VAULT_TOKEN : '', VAULT_ADDR : '', SSH_AUTH_SOCK : ''};
  const expected = {CI_PROJECT_PATH : 'Team/sub/App', CI_PROJECT_NAME : 'App', CI_PROJECT_NAMESPACE : 'Team/sub', CI_PROJECT_PATH_SLUG : 'team-sub-app'};
  for(const cli of [path.resolve(__dirname, '..', 'cmd', 'vauth.js')]) {
    for(const args of [['gitlab'], ['env', '--source', '--gitlab']]) {
      const output = await exec(process.execPath, [cli, ...args], {cwd : project, env});
      const names = [...output.stdout.matchAll(/^export ([A-Z_]+)=/gm)].map(match => match[1]);
      assert.deepEqual(names, Object.keys(expected));
      for(const [key, value] of Object.entries(expected)) assert.ok(output.stdout.includes(`export ${key}='${value}'`));
      if(args[0] === 'gitlab') assert.match(output.stderr, /commands list/);
      else assert.equal(output.stderr, '');
      assert.equal(fs.readFileSync(file, 'utf8'), body);
      assert.equal(fs.existsSync(path.join(project, '.vauthrc')), false);
    }
  }
  assert.equal(requests, 0);
});

test('constructor with env.gitlab rejects missing CI variables before authentication', async t => {
  const {client, requests} = await fixture(t);
  const keys = ['CI_PROJECT_PATH', 'CI_PROJECT_NAME', 'CI_PROJECT_NAMESPACE', 'CI_PROJECT_PATH_SLUG'];
  const previous = Object.fromEntries(keys.map(key => [key, process.env[key]]));
  try {
    for(const key of keys) delete process.env[key];
    assert.throws(() => client({rc : {env : {gitlab : true, map : {KEEP : 'literal'}}}}), /Run venv --gitlab first/);
    assert.deepEqual(requests, []);
    for(const key of keys) process.env[key] = 'provided';
    const v = client({rc : {env : {gitlab : true, map : {KEEP : 'literal'}}}});
    const env = await v.Env();
    assert.equal(env.KEEP, 'literal');
    assert.ok(requests.length > 0);
  } finally {
    for(const [key, value] of Object.entries(previous)) {
      if(value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test('env.map scalar strings leave the raw RC types untouched', async t => {
  const map = {TEXT : 'hello', BOOL : true, NUMBER : 42, NULL : null, LARGE : 1e20, SMALL : 1e-7, ZERO : -0};
  const v = configuredClient(t, {env : {map}});
  assert.deepEqual(await v.Env(), {TEXT : 'hello', BOOL : 'true', NUMBER : '42', NULL : '', LARGE : '100000000000000000000', SMALL : '1e-7', ZERO : '0'});
  assert.equal(v.RC.env.map.BOOL, true);
  assert.equal(v.RC.env.map.NUMBER, 42);
  assert.equal(v.RC.env.map.NULL, null);
  assert.ok(Object.isFrozen(v.RC.env.map));
});

test('env.map rejects objects and arrays before and after macro expansion', async t => {
  const f = await fixture(t, {metadata : {SCALAR : 42, BOOL : false, NULL : null, OBJECT : {x : 1}, ARRAY : ['x']}});
  const v = f.client();
  for(const value of [{x : 1}, ['x'], ['$${profile.SCALAR}'], '$${profile.OBJECT}', '$${profile.ARRAY}', '$${profile}']) {
    v.config = {env : {map : {VALUE : value}}};
    await assert.rejects(v.Env(), /Invalid environment value 'VALUE' in env.map: expected a scalar/);
  }
  v.config = {env : {map : {NUMBER : '$${profile.SCALAR}', BOOL : '$${profile.BOOL}', NULL : '$${profile.NULL}'}, git : true}};
  const env = await v.Env();
  assert.equal(env.NUMBER, '42');
  assert.equal(env.BOOL, 'false');
  assert.equal(env.NULL, '');
  assert.equal(env.GIT_AUTHOR_EMAIL, '');
  assert.equal(env.GIT_COMMITTER_EMAIL, '');
});
