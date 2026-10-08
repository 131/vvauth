'use strict';

const assert = require('node:assert/strict');
const {test} = require('node:test');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const {execFile, spawn} = require('child_process');
const {promisify, format} = require('util');
const exec = promisify(execFile);
const Vauth = require('../index');

const HOUR = 60 * 60;

async function fixture(t, options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vvauth-test-'));
  const file = path.join(directory, '.vauth', 'token.json');
  const requests = [];
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
      res.end(JSON.stringify({data : {metadata : {}}}));
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
  const client = () => {
    // Avoid reading the real user's environment/configuration/cache.
    const instance = Object.create(Vauth.prototype);
    instance.rc = {jwt_auth : {path : 'jwt', jwt : 'test-jwt', role : 'test-role'}};
    instance.VAULT_ADDR = `http://127.0.0.1:${server.address().port}`;
    instance._token_cache_file = () => file;
    return instance;
  };
  const remaining = (instance, ttl) => {
    const cache = JSON.parse(fs.readFileSync(file, 'utf8'));
    cache.tokens[instance._token_cache_key()].expires_at = ttl === 0 ? null : Date.now() + ttl * 1000;
    fs.writeFileSync(file, JSON.stringify(cache));
  };
  const seed = (instance, lease = 12 * HOUR) => {
    instance._save_cached_token('cached-token', {lease_duration : lease, renewable : options.renewable !== false});
    if(options.ttl !== undefined)
      remaining(instance, options.ttl);
  };
  const read = instance => JSON.parse(fs.readFileSync(file, 'utf8')).tokens[instance._token_cache_key()];
  return {client, seed, read, requests, file, remaining};
}

test('login persists a token; a new instance reuses it without logging in', async t => {
  const {client, read, requests, file} = await fixture(t);
  const first = client();
  assert.equal(await first.connect(), 'fresh-token');
  assert.equal(read(first).token, 'fresh-token');
  assert.ok(read(first).expires_at > Date.now() + 23 * HOUR * 1000);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
  const second = client();
  assert.equal(await second.connect(), 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
  assert.deepEqual(fs.readdirSync(path.dirname(file)), ['token.json']);
});

test('a token in the last third of its lease is renewed and saved', async t => {
  const {client, seed, read, requests} = await fixture(t, {ttl : HOUR});
  const instance = client();
  seed(instance, 12 * HOUR);
  assert.equal(await instance.connect(), 'cached-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/token/renew-self']);
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].token, 'cached-token');
  assert.ok(read(instance).expires_at > Date.now() + 23 * HOUR * 1000);
});

test('more than one third remaining does not trigger renewal', async t => {
  const {client, seed, requests} = await fixture(t, {ttl : 4 * HOUR + 1});
  const instance = client();
  seed(instance);
  assert.equal(await instance.connect(), 'cached-token');
  assert.equal(requests.length, 0);
});

test('expired cached tokens are replaced with a new persisted login', async t => {
  const {client, seed, read, requests, file} = await fixture(t);
  const instance = client();
  seed(instance);
  const cache = JSON.parse(fs.readFileSync(file, 'utf8'));
  cache.tokens[instance._token_cache_key()].expires_at = Date.now() - 1000;
  fs.writeFileSync(file, JSON.stringify(cache));
  assert.equal(await instance.connect(), 'fresh-token');
  assert.equal(read(instance).token, 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
});

test('cached tokens are reused without checking revocation', async t => {
  const {client, seed, requests} = await fixture(t, {lookup_status : 403});
  const instance = client();
  seed(instance);
  assert.equal(await instance.connect(), 'cached-token');
  assert.deepEqual(requests, []);
  await assert.rejects(instance._lookup_token(instance.VAULT_TOKEN));
});

test('nonrenewable tokens nearing expiry trigger reauthentication', async t => {
  const {client, seed, requests} = await fixture(t, {ttl : HOUR, renewable : false});
  const instance = client();
  seed(instance);
  assert.equal(await instance.connect(), 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
});

for(const status of [400, 403]) {
  test(`rejected renewal (${status}) triggers a new persisted login`, async t => {
    const {client, seed, read, requests} = await fixture(t, {ttl : HOUR, renew_status : status});
    const instance = client();
    seed(instance);
    assert.equal(await instance.connect(), 'fresh-token');
    assert.equal(read(instance).token, 'fresh-token');
    assert.deepEqual(requests.map(req => req.path), ['/v1/auth/token/renew-self', '/v1/auth/jwt/login']);
  });
}

test('server failures do not generate extra tokens, and connect can be retried', async t => {
  const {client, seed, requests} = await fixture(t, {lookup_status : 500});
  const instance = client();
  seed(instance);
  instance.VAULT_TOKEN = 'uncached-token';
  await assert.rejects(instance.connect());
  await assert.rejects(instance.connect());
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/token/lookup-self', '/v1/auth/token/lookup-self']);
});

test('renewal server failures do not generate extra tokens', async t => {
  const {client, seed, requests} = await fixture(t, {ttl : HOUR, renew_status : 500});
  const instance = client();
  seed(instance);
  await assert.rejects(instance.connect());
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/token/renew-self']);
});

test('an existing environment token is respected and cached', async t => {
  const {client, seed, read, requests} = await fixture(t);
  const instance = client();
  seed(instance);
  instance.VAULT_TOKEN = 'environment-token';
  assert.equal(await instance.connect(), 'environment-token');
  assert.equal(read(instance).token, 'environment-token');
  assert.equal(requests[0].token, 'environment-token');
  assert.equal(requests.length, 1);
});

test('nonexpiring tokens are reused without renewal', async t => {
  const {client, seed, read, requests} = await fixture(t, {ttl : 0});
  const instance = client();
  seed(instance, 0);
  assert.equal(await instance.connect(), 'cached-token');
  assert.equal(read(instance).expires_at, null);
  assert.equal(requests.length, 0);
});

test('corrupt caches are replaced with a valid cache', async t => {
  const {client, read, file} = await fixture(t);
  fs.mkdirSync(path.dirname(file));
  fs.writeFileSync(file, '{broken');
  const instance = client();
  assert.equal(await instance.connect(), 'fresh-token');
  assert.equal(read(instance).token, 'fresh-token');
});

test('cache entries are isolated by Vault address and authentication configuration', async t => {
  const {client, seed, read, file} = await fixture(t);
  const first = client();
  seed(first);
  const second = client();
  second.rc.jwt_auth.role = 'other-role';
  assert.equal(await second.connect(), 'fresh-token');
  assert.equal(read(first).token, 'cached-token');
  assert.equal(read(second).token, 'fresh-token');
  const third = client();
  third.VAULT_ADDR = 'http://other-vault.test';
  assert.notEqual(third._token_cache_key(), first._token_cache_key());
  assert.equal(Object.keys(JSON.parse(fs.readFileSync(file, 'utf8')).tokens).length, 2);
  assert.ok(!fs.readFileSync(file, 'utf8').includes('test-jwt'));
});

test('repeated connect calls reuse the established connection', async t => {
  const {client, requests} = await fixture(t);
  const instance = client();
  assert.equal(await instance.connect(), 'fresh-token');
  assert.equal(await instance.connect(), 'fresh-token');
  assert.equal(requests.length, 1);
});

test('an unwritable cache does not prevent login', async t => {
  const {client, file} = await fixture(t);
  fs.writeFileSync(path.dirname(file), 'not a directory');
  assert.equal(await client().connect(), 'fresh-token');
});

test('an invalid token without an auth method fails rather than exporting undefined', async t => {
  const {client, seed} = await fixture(t, {lookup_status : 403});
  const instance = client();
  instance.rc = {};
  seed(instance);
  instance.VAULT_TOKEN = 'uncached-token';
  await assert.rejects(instance.connect(), /no authentication method/);
});

test('--renew ignores both environment and cached tokens and saves a new token', async t => {
  const {client, seed, read, requests} = await fixture(t);
  const instance = client();
  seed(instance);
  instance.VAULT_TOKEN = 'environment-token';
  assert.equal(await instance.connect(true), 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
  assert.equal(read(instance).token, 'fresh-token');
  assert.ok(read(instance).expires_at > Date.now() + 23 * HOUR * 1000);
});

test('--renew replaces the token of a previously connected instance', async t => {
  const {client, seed, read, requests} = await fixture(t);
  const instance = client();
  seed(instance);
  await instance.connect();
  assert.equal(await instance.connect(true), 'fresh-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
  assert.equal(read(instance).token, 'fresh-token');
});

test('each successive --renew call forces a new login', async t => {
  const {client, requests} = await fixture(t);
  const instance = client();
  assert.equal(await instance.connect(true), 'fresh-token');
  assert.equal(await instance.connect(true), 'fresh-token');
  assert.equal(requests.length, 2);
});

test('--renew without an authentication method fails even with no cached token', async t => {
  const {client} = await fixture(t);
  const instance = client();
  instance.rc = {};
  await assert.rejects(instance.connect(true), /no authentication method/);
});

for(const flag of ['renew']) {
  test(`env forwards --${flag} into forced reauthentication`, async t => {
    const {client} = await fixture(t);
    const instance = client();
    let forced;
    instance.connect = async renew => { forced = renew; };
    assert.deepEqual(await instance.env(false, true), {VAULT_ADDR : instance.VAULT_ADDR});
    assert.equal(forced, true);
  });

  for(const command of ['env', 'login']) {
    test(`real CLI ${command} --${flag} generates and caches a new token`, async t => {
      const {client, seed, read, requests, file} = await fixture(t);
      const instance = client();
      seed(instance);
      const home = path.dirname(path.dirname(file));
      const rc = path.join(home, '.vauthrc');
      fs.writeFileSync(rc, JSON.stringify({vault_addr : instance.VAULT_ADDR, ...instance.rc}));
      const options = {
        cwd : home,
        env : {...process.env, HOME : home, VAUTHRC : rc, VAULT_TOKEN : 'environment-token', SSH_AUTH_SOCK : ''},
      };
      const cli = path.resolve(__dirname, '..', 'index.js');
      const output = await exec(process.execPath, [cli, command, '--source', `--${flag}`], options);
      assert.ok(output.stdout.includes("export VAULT_TOKEN='fresh-token'"));
      assert.ok(!output.stdout.includes('Vauth token: '));
      assert.equal(output.stderr.split('\n').filter(line => line === `Vauth token: generated · ${instance.VAULT_ADDR} · 1d`).length, 1);
      assert.ok(!output.stderr.includes('Vauth token: renewed'));
      assert.ok(!output.stderr.includes('fresh-token'));
      assert.ok(!output.stderr.includes('environment-token'));
      assert.deepEqual(requests.filter(req => !req.path.startsWith('/v1/identity/')).map(req => req.path), command === 'env'
        ? ['/v1/auth/jwt/login', '/v1/auth/token/lookup-self'] : ['/v1/auth/jwt/login']);
      assert.equal(read(instance).token, 'fresh-token');
      assert.equal(fs.statSync(file).mode & 0o777, 0o600);
      requests.length = 0;
      const reused = await exec(process.execPath, [cli, command, '--source'], {
        ...options, env : {...options.env, VAULT_TOKEN : ''},
      });
      assert.ok(reused.stdout.includes("export VAULT_TOKEN='fresh-token'"));
      assert.equal(reused.stderr.split('\n').filter(line => line.startsWith('Vauth token: ')).length, 1);
      assert.ok(reused.stderr.includes(`Vauth token: reused · ${instance.VAULT_ADDR} · 1d`));
      assert.ok(!requests.some(req => req.path.endsWith('/login') || req.path.endsWith('/renew-self')));
    });
  }
}

test('installed venv forwards --renew through the real CLI', async t => {
  const {client, seed, read, requests, file} = await fixture(t);
  const instance = client();
  seed(instance);
  const home = path.dirname(path.dirname(file));
  const original_home = os.homedir;
  instance._function_exists = async () => 1;
  try {
    os.homedir = () => home;
    await instance.install();
  } finally {
    os.homedir = original_home;
  }
  const declaration = fs.readFileSync(path.join(home, '.bashrc'), 'utf8');
  assert.ok(declaration.includes('vauth env --source "$@"'));
  const bin = path.join(home, 'bin');
  fs.mkdirSync(bin);
  fs.symlinkSync(path.resolve(__dirname, '..', 'index.js'), path.join(bin, 'vauth'));
  const rc = path.join(home, '.vauthrc');
  fs.writeFileSync(rc, JSON.stringify({vault_addr : instance.VAULT_ADDR, ...instance.rc}));
  const options = {
    cwd : home,
    env : {...process.env, HOME : home, VAUTHRC : rc, VAULT_TOKEN : '', SSH_AUTH_SOCK : '', PATH : `${bin}:${process.env.PATH}`},
  };
  const initial = await exec('bash', ['-c', `${declaration}\nvenv; printf '%s' "$VAULT_TOKEN"`], options);
  assert.equal(initial.stdout, 'cached-token');
  assert.equal(initial.stderr.split('\n').filter(line => line.startsWith('Vauth token: ')).length, 1);
  assert.ok(initial.stderr.includes(`Vauth token: reused · ${instance.VAULT_ADDR} · 12h`));
  assert.ok(!requests.some(req => req.path.endsWith('/login') || req.path.endsWith('/renew-self')));
  for(const flag of ['--renew']) {
    const output = await exec('bash', ['-c', `${declaration}\nvenv ${flag}; printf '%s' "$VAULT_TOKEN"`], options);
    assert.equal(output.stdout, 'fresh-token');
    assert.equal(output.stderr.split('\n').filter(line => line === `Vauth token: generated · ${instance.VAULT_ADDR} · 1d`).length, 1);
    assert.ok(!output.stderr.includes('Vauth token: renewed'));
    assert.ok(!output.stderr.includes('fresh-token'));
    assert.equal(read(instance).token, 'fresh-token');
  }
  assert.equal(requests.filter(req => req.path.endsWith('/login')).length, 1);
  assert.ok(!requests.some(req => req.path.endsWith('/renew-self')));
});

for(const answer of ['yes', 'no', '']) {
  test(`install asks before overriding an existing function: ${JSON.stringify(answer)}`, async t => {
    const {file} = await fixture(t);
    const home = path.dirname(path.dirname(file));
    const bashrc = path.join(home, '.bashrc');
    const original = '# before\nfunction venv() { source <(/usr/bin/env vauth env --source); }\n# after\n';
    fs.writeFileSync(bashrc, original);
    const module_path = path.resolve(__dirname, '..', 'index.js');
    const script = `const Vauth = require(${JSON.stringify(module_path)});
      const instance = Object.create(Vauth.prototype);
      instance._function_exists = async () => 0;
      instance.install().catch(() => process.exit(1));`;
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
  instance.VAULT_ADDR = 'https://vault.example.test';
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
      `Vauth token: reused · ${instance.VAULT_ADDR} · ${duration}`,
    ]);
  }
  assert.deepEqual(captureStatus(() => instance._token_status('renewed', {lease_duration : HOUR + 60})), [
    `Vauth token: renewed · ${instance.VAULT_ADDR} · 1h 1m`,
  ]);
  assert.deepEqual(captureStatus(() => instance._token_status('generated', {lease_duration : 0})), [
    `Vauth token: generated · ${instance.VAULT_ADDR} · valid indefinitely`,
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
    seed(instance);
    const calls = [];
    instance._token_status = (operation, metadata) => {
      calls.push(...captureStatus(() => Vauth.prototype._token_status.call(instance, operation, metadata)));
    };
    await instance.connect();
    await instance.connect();
    const validity = options.duration ? `valid for ${options.duration}` : 'valid indefinitely';
    assert.deepEqual(calls, [`Vauth token: ${options.operation} · ${instance.VAULT_ADDR} · ${validity.replace(/^valid for /, '')}`]);
  });
}

test('failed connections never announce successful token status', async t => {
  const {client, seed} = await fixture(t, {lookup_status : 500});
  const instance = client();
  seed(instance);
  instance.VAULT_TOKEN = 'uncached-token';
  const calls = [];
  instance._token_status = operation => calls.push(operation);
  await assert.rejects(instance.connect());
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
    seed(instance, lease);
    await instance.connect();
    assert.equal(requests.some(req => req.path.endsWith('/renew-self')), renew);
    assert.equal(read(instance).lease_duration, renew ? 24 * HOUR : lease);
  });
}

test('lookups never reset the original lease duration', async t => {
  const options = {ttl : 20 * HOUR};
  const {client, seed, read, requests, remaining} = await fixture(t, options);
  const instance = client();
  seed(instance, 24 * HOUR);
  await instance.connect();
  assert.equal(read(instance).lease_duration, 24 * HOUR);
  remaining(instance, 12 * HOUR);
  await client().connect();
  assert.equal(read(instance).lease_duration, 24 * HOUR);
  remaining(instance, 8 * HOUR);
  await client().connect();
  assert.equal(requests.filter(req => req.path.endsWith('/renew-self')).length, 1);
});

test('renewal updates the lease baseline to the newly granted duration', async t => {
  const options = {ttl : 20 * 60};
  const {client, seed, read, requests, remaining} = await fixture(t, options);
  const instance = client();
  seed(instance, HOUR);
  await instance.connect();
  assert.equal(read(instance).lease_duration, 24 * HOUR);
  remaining(instance, 8 * HOUR);
  await client().connect();
  assert.equal(requests.filter(req => req.path.endsWith('/renew-self')).length, 2);
});

test('normal reuse never writes the token cache', async t => {
  const {client, seed, file, requests} = await fixture(t);
  const instance = client();
  seed(instance);
  instance.VAULT_TOKEN = 'cached-token';
  const before = fs.readFileSync(file, 'utf8');
  const stat = fs.statSync(file);
  instance._save_cached_token = () => { throw new Error('Reuse must not write'); };
  assert.equal(await instance.connect(), 'cached-token');
  assert.equal(fs.readFileSync(file, 'utf8'), before);
  assert.equal(fs.statSync(file).ino, stat.ino);
  assert.equal(fs.statSync(file).mtimeMs, stat.mtimeMs);
  assert.deepEqual(requests, []);
});


test('lookup returns the lease duration and preserves a cached renewal baseline', async t => {
  const {client, seed, requests} = await fixture(t, {ttl : HOUR, creation_ttl : 24 * HOUR});
  const instance = client();
  const uncached = await instance._lookup_token('environment-token');
  assert.equal(uncached.lease_duration, 24 * HOUR);
  assert.equal(uncached.ttl, HOUR);
  seed(instance, 12 * HOUR);
  const cached = await instance._lookup_token('cached-token');
  assert.equal(cached.lease_duration, 12 * HOUR);
  assert.equal(requests.length, 2);
});

test('token_cache false skips all cache filesystem access', async t => {
  const {client, requests, file} = await fixture(t);
  const instance = client();
  instance.rc.token_cache = false;
  instance._token_cache_file = () => { throw new Error('Disabled cache must not access disk'); };
  assert.equal(await instance.connect(), 'fresh-token');
  assert.equal(fs.existsSync(file), false);
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/jwt/login']);
});

test('token_cache false ignores existing tokens on disk without deleting them', async t => {
  const {client, seed, requests, file} = await fixture(t);
  const instance = client();
  seed(instance);
  const before = fs.readFileSync(file, 'utf8');
  instance.rc.token_cache = false;
  assert.equal(await instance.connect(), 'fresh-token');
  assert.equal(fs.readFileSync(file, 'utf8'), before);
  const second = client();
  second.rc.token_cache = false;
  assert.equal(await second.connect(), 'fresh-token');
  assert.equal(requests.filter(req => req.path.endsWith('/login')).length, 2);
});

test('token_cache false still respects an environment token without persisting it', async t => {
  const {client, requests, file} = await fixture(t);
  const instance = client();
  instance.rc.token_cache = false;
  instance.VAULT_TOKEN = 'environment-token';
  assert.equal(await instance.connect(), 'environment-token');
  assert.deepEqual(requests.map(req => req.path), ['/v1/auth/token/lookup-self']);
  assert.equal(fs.existsSync(file), false);
});

test('real CLI reads token_cache false from .vauthrc', async t => {
  const {client, file, requests} = await fixture(t);
  const instance = client();
  const home = path.dirname(path.dirname(file));
  const rc = path.join(home, '.vauthrc');
  fs.writeFileSync(rc, JSON.stringify({vault_addr : instance.VAULT_ADDR, ...instance.rc, token_cache : false}));
  const cli = path.resolve(__dirname, '..', 'index.js');
  for(let i = 0; i < 2; i++) {
    const output = await exec(process.execPath, [cli, 'login', '--source'], {
      cwd : home,
      env : {...process.env, HOME : home, VAUTHRC : rc, VAULT_TOKEN : '', SSH_AUTH_SOCK : ''},
    });
    assert.ok(output.stdout.includes("export VAULT_TOKEN='fresh-token'"));
    assert.ok(output.stderr.includes('Vauth token: generated'));
  }
  assert.equal(fs.existsSync(file), false);
  assert.equal(requests.filter(req => req.path.endsWith('/login')).length, 2);
});
