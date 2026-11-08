'use strict';

const assert = require('node:assert/strict');
const {test} = require('node:test');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {spawnSync} = require('child_process');
const {createHash} = require('crypto');
const Vvauth = require('../index');

function client(options = {}) {
  const v = Object.create(Vvauth.prototype);
  Object.defineProperties(v, {
    VAULT_TOKEN : {value : options.parent || 'synthetic-parent', writable : true},
    VAULT_ADDR : {value : 'https://synthetic.invalid'},
    RC : {value : {token_cache : false}},
  });
  v.config = {delegate : ['vauth-profile-ro', 'project-ro'], env : {map : {
    VAULT_ROUTER_TOKEN : '$${delegate.vauth-profile-ro}', PROJECT_TOKEN : '$$delegate.project-ro',
  }}};
  v.calls = [];
  v.Connect = async renew => { v.calls.push(['connect', renew]); return v.VAULT_TOKEN; };
  v.GetProfile = async renew => { await v.Connect(renew); return {profile : {}, database : {}}; };
  v.LookupSelf = async token => { v.calls.push(['lookup', token]); return {ttl : options.ttl === undefined ? 1234.5 : options.ttl}; };
  v.Request = async (method, route, token, payload) => {
    v.calls.push(['create', route, token, payload]);
    if(options.error) throw new Error('synthetic issuance denied');
    if(options.body !== undefined) return {body : options.body};
    return {body : JSON.stringify({auth : options.auth === undefined ? {client_token : `synthetic-child-${v.calls.length}`, lease_duration : 1000} : options.auth})};
  };
  return v;
}

const creations = v => v.calls.filter(call => call[0] === 'create');

test('native config, multiple roles and explicit exports retain the human token', async t => {
  t.mock.method(Date, 'now', () => 100000);
  const v = client();
  const env = await v.Env();
  assert.equal(env.VAULT_TOKEN, 'synthetic-parent');
  assert.notEqual(env.VAULT_ROUTER_TOKEN, env.VAULT_TOKEN);
  assert.notEqual(env.PROJECT_TOKEN, env.VAULT_ROUTER_TOKEN);
  assert.deepEqual(Object.keys(env), ['VAULT_TOKEN', 'VAULT_ADDR', 'VAULT_ROUTER_TOKEN', 'PROJECT_TOKEN']);
  assert.deepEqual(creations(v)[0].slice(1), ['auth/token/create/vauth-profile-ro', 'synthetic-parent', {
    ttl : '1234.5s', renewable : false, no_default_policy : true, type : 'service',
  }]);
  v.config.env.map = {};
  assert.deepEqual(Object.keys(await v.Env()), ['VAULT_TOKEN', 'VAULT_ADDR']);
});

test('full TTL memory reuse, expiry, renew, parent and role isolation with disk off', async () => {
  const v = client();
  const now = Date.now;
  let clock = 100000;
  Date.now = () => clock;
  try {
    const first = await v.Delegate('vauth-profile-ro');
    clock += 999999;
    assert.equal(await v.Delegate('vauth-profile-ro'), first);
    assert.equal(creations(v).length, 1);
    assert.equal(v.calls.filter(call => call[0] === 'lookup').length, 1);
    clock++;
    assert.notEqual(await v.Delegate('vauth-profile-ro'), first);
    assert.notEqual(await v.Delegate('vauth-profile-ro', true), first);
    await v.Delegate('project-ro');
    v.VAULT_TOKEN = 'synthetic-other-parent';
    await v.Delegate('vauth-profile-ro');
    assert.equal(creations(v).length, 5);
    assert.ok(v.calls.filter(call => call[0] === 'connect').every(call => call[1] === false));
    assert.ok([...v._delegates.keys()].every(key => !key.includes('synthetic')));
    assert.ok([...v._delegates.values()].every(cache => !JSON.stringify(cache).includes('parent')));
  } finally { Date.now = now; }
});

test('unknown macros, issuance and invalid responses fail without partial output', async () => {
  for(const options of [{error : true}, {body : '{malformed'}, {body : 'null'}, {auth : null}, {auth : {}},
    {auth : {client_token : 'synthetic-parent', lease_duration : 10}},
    {auth : {client_token : 'synthetic-child', lease_duration : 0}},
    {auth : {client_token : 'synthetic-child', lease_duration : 2000}},
    {auth : {client_token : 'synthetic-child', lease_duration : '10'}}, {ttl : 0}, {ttl : -1}]) {
    const v = client(options);
    let published = false;
    v.PublishEnv = () => { published = true; };
    await assert.rejects(v.Env(true));
    assert.equal(published, false);
  }
  for(const macro of ['$${delegate.unknown}', '$$delegate.unknown', '$${delegate}']) {
    const v = client();
    v.config.env.map = {OK : 'value', BAD : macro};
    let published = false;
    v.PublishEnv = () => { published = true; };
    await assert.rejects(v.Env(true), /Unknown Vault delegation/);
    assert.equal(published, false);
  }
  const v = client();
  delete v.config.delegate;
  v.config.env.map = {OK : 'value'};
  assert.equal((await v.Env()).OK, 'value');
  assert.equal(creations(v).length, 0);
  for(const role of ['', '../other', '.', '..', {}])
    await assert.rejects(v.Delegate(role));
});

test('encrypted disk cache reuse uses no child or parent lookup', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vvauth-delegate-'));
  t.after(() => fs.rmSync(directory, {recursive : true, force : true}));
  const agent = spawnSync('ssh-agent', ['-s'], {encoding : 'utf8'});
  if(agent.status !== 0) {
    t.skip('sandbox cannot start a synthetic ssh-agent');
    return;
  }
  const socket = agent.stdout.match(/SSH_AUTH_SOCK=([^;]+)/)[1];
  const pid = Number(agent.stdout.match(/SSH_AGENT_PID=(\d+)/)[1]);
  t.after(() => process.kill(pid));
  const previous = {};
  for(const key of ['HOME', 'USERPROFILE', 'SSH_AUTH_SOCK', 'SSH_AGENT_CRYPT_KEY', 'VAUTH_USER_IDENTITY', 'VAUTH_USER_MAIL']) {
    previous[key] = process.env[key];
    delete process.env[key];
  }
  Object.assign(process.env, {HOME : directory, USERPROFILE : directory, SSH_AUTH_SOCK : socket});
  t.after(() => {
    for(const [key, value] of Object.entries(previous)) {
      if(value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
  const key = path.join(directory, 'key');
  assert.equal(spawnSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', key]).status, 0);
  assert.equal(spawnSync('ssh-add', [key]).status, 0);
  const v = client();
  v.RC.token_cache = true;
  const token = await v.Delegate('vauth-profile-ro');
  const hash = createHash('sha256').update(JSON.stringify([v.VAULT_ADDR, v.VAULT_TOKEN, 'vauth-profile-ro'])).digest('hex');
  const file = path.join(directory, '.vauth', 'delegates', hash + '.creds');
  const armor = fs.readFileSync(file, 'utf8');
  assert.ok(armor.startsWith('ssh-agent-crypt:v3:'));
  assert.ok(!armor.includes(token) && !armor.includes(v.VAULT_TOKEN));
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  const next = client();
  next.RC.token_cache = true;
  assert.equal(await next.Delegate('vauth-profile-ro'), token);
  assert.equal(next.calls.filter(call => call[0] !== 'connect').length, 0);
});

test('approved YAML loads root role list without auth defaults or policy assertions', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vvauth-native-'));
  t.after(() => fs.rmSync(directory, {recursive : true, force : true}));
  const file = path.join(directory, '.vauthrc');
  fs.writeFileSync(file, `vault_addr: https://vault.elipsdev.net
ssh_auth:
  role: $\u0024{env.VAUTH_USER_LOGIN}
delegate:
  - vauth-profile-ro
env:
  map:
    VAULT_ROUTER_TOKEN: $\u0024{delegate.vauth-profile-ro}
`);
  const script = `const assert=require('assert/strict');const V=require('./index');const v=new V();
assert.deepEqual(v.config.delegate,['vauth-profile-ro']);
assert.equal(v.config.env.map.VAULT_ROUTER_TOKEN,'$\u0024{delegate.vauth-profile-ro}');
assert.deepEqual(Object.keys(v.RC),['vault_addr','ssh_auth','delegate','env']);`;
  const child = spawnSync('node', ['-e', script], {encoding : 'utf8', env : {
    PATH : process.env.PATH, HOME : directory, VAUTHRC : file, VAUTH_USER_LOGIN : 'synthetic-user',
  }});
  assert.equal(child.status, 0, child.stderr);
});

test('only an invalid parent triggers one normal login retry, never issuance denial', async t => {
  t.mock.method(Date, 'now', () => 100000);
  const v = client();
  let lookups = 0;
  v.LookupSelf = async () => {
    if(++lookups === 1) throw new (require('vauth-login').HTTPError)(403, 'synthetic denial');
    return {ttl : 1000};
  };
  v.Connect = async renew => {
    v.calls.push(['connect', renew]);
    if(renew) v.VAULT_TOKEN = 'synthetic-new-parent';
  };
  await v.Delegate('vauth-profile-ro', true);
  assert.equal(v.calls.filter(call => call[0] === 'connect' && call[1]).length, 1);
  assert.equal(creations(v)[0][2], 'synthetic-new-parent');
});

test('delayed responses consume parent TTL and keep the child request-time deadline', async t => {
  let clock = 100000;
  t.mock.method(Date, 'now', () => clock);
  const v = client({ttl : 10, auth : {client_token : 'synthetic-delayed-child', lease_duration : 5}});
  const lookup = v.LookupSelf.bind(v), create = v.Request.bind(v);
  v.LookupSelf = async token => {
    const info = await lookup(token);
    clock += 2000;
    return info;
  };
  v.Request = async (...args) => {
    const response = await create(...args);
    clock += 3000;
    return response;
  };
  const token = await v.Delegate('role');
  assert.equal(creations(v)[0][3].ttl, '8s');
  assert.equal([...v._delegates.values()][0].expires_at, 107000);
  clock = 106999;
  assert.equal(await v.Delegate('role'), token);
  assert.equal(creations(v).length, 1);
  assert.equal(v.calls.filter(call => call[0] === 'lookup').length, 1);
  clock = 107000;
  await v.Delegate('role');
  assert.equal(creations(v).length, 2);
  assert.ok(v.calls.filter(call => call[0] === 'connect').every(call => call[1] === false));
});

test('a child expired on arrival is never cached or published', async t => {
  let clock = 100000;
  t.mock.method(Date, 'now', () => clock);
  for(const delay of [5000, 6000]) {
    const v = client({ttl : 10, auth : {client_token : 'synthetic-delayed-child', lease_duration : 5}});
    const create = v.Request.bind(v);
    v.Request = async (...args) => {
      const response = await create(...args);
      clock += delay;
      return response;
    };
    let published = false;
    v.PublishEnv = () => { published = true; };
    await assert.rejects(v.Env(true), /delegation/);
    assert.equal(v._delegates.size, 0);
    assert.equal(published, false);
  }
});

test('parent lifetime consumed by lookup prevents issuance without another login', async t => {
  let clock = 100000;
  t.mock.method(Date, 'now', () => clock);
  for(const delay of [10000, 11000]) {
    const v = client({ttl : 10});
    v.LookupSelf = async () => { clock += delay; return {ttl : 10}; };
    await assert.rejects(v.Delegate('role'), /parent delegation TTL/);
    assert.equal(creations(v).length, 0);
    assert.deepEqual(v.calls, [['connect', false]]);
  }
});

test('parent lookup anchor resets only after the existing login retry', async t => {
  let clock = 100000, lookups = 0;
  t.mock.method(Date, 'now', () => clock);
  const v = client({auth : {client_token : 'synthetic-child', lease_duration : 5}});
  v.LookupSelf = async () => {
    if(++lookups === 1) {
      clock += 100000;
      throw new (require('vauth-login').HTTPError)(403, 'synthetic denial');
    }
    clock += 2000;
    return {ttl : 10};
  };
  v.Connect = async renew => {
    v.calls.push(['connect', renew]);
    if(renew) {
      clock += 100000;
      v.VAULT_TOKEN = 'synthetic-new-parent';
    }
  };
  await v.Delegate('role');
  assert.equal(creations(v)[0][3].ttl, '8s');
  assert.equal(v.calls.filter(call => call[0] === 'connect' && call[1]).length, 1);
});
