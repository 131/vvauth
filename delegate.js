'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const {createHash, randomUUID} = require('crypto');
const VauthLogin = require('vauth-login');
const {encrypt, decrypt} = require('ssh-agent-crypt');

const roleName = /^[A-Za-z0-9_.-]+$/;
const valid = (cache, parent, now) => cache && typeof cache.token === 'string' && cache.token && cache.token !== parent && Number.isFinite(cache.expires_at) && cache.expires_at > now;

module.exports = {
  async Delegate(role, renew = false) {
    if(typeof role !== 'string' || !roleName.test(role) || ['.', '..'].includes(role))
      throw new Error('Invalid Vault delegation role');
    // Renewal belongs to the child; reuse the established parent login.
    await this.Connect(false);
    let parent = this.VAULT_TOKEN;
    if(!parent || !this.VAULT_ADDR)
      throw new Error('Vault delegation requires a parent token and address');
    let key = createHash('sha256').update(JSON.stringify([this.VAULT_ADDR.replace(/^\/+|\/+$/g, ''), parent, role])).digest('hex');
    let file = path.join(os.homedir(), '.vauth', 'delegates', key + '.creds');
    this._delegates ||= new Map();
    const disk = this.RC.token_cache !== false && (process.env.SSH_AUTH_SOCK || process.platform === 'win32');
    let cache = this._delegates.get(key);
    if(!renew && !valid(cache, parent, Date.now()) && disk)
      try { cache = JSON.parse(await decrypt(fs.readFileSync(file))); } catch(err) {}
    if(!renew && valid(cache, parent, Date.now())) {
      this._delegates.set(key, cache);
      return cache.token;
    }
    let info;
    let lookupStarted = Date.now();
    try {
      info = await this.LookupSelf(parent);
    } catch(err) {
      if(!(err instanceof VauthLogin.HTTPError) || ![400, 403].includes(err.status))
        throw err;
      await this.Connect(true);
      parent = this.VAULT_TOKEN;
      if(!parent)
        throw new Error('Vault delegation requires a parent token');
      key = createHash('sha256').update(JSON.stringify([this.VAULT_ADDR.replace(/^\/+|\/+$/g, ''), parent, role])).digest('hex');
      file = path.join(os.homedir(), '.vauth', 'delegates', key + '.creds');
      lookupStarted = Date.now();
      info = await this.LookupSelf(parent);
    }
    // Anchor server TTLs at request start; response time is not extra life.
    const createStarted = Date.now();
    const ttl = info.ttl - (createStarted - lookupStarted) / 1000;
    if(!Number.isFinite(ttl) || ttl <= 0)
      throw new Error('Invalid Vault parent delegation TTL');
    const {body} = await this.Request('POST', `auth/token/create/${role}`, parent, {
      ttl : `${ttl}s`, renewable : false, no_default_policy : true, type : 'service',
    }, 200);
    let response;
    try { response = JSON.parse(body); } catch(err) {
      throw new Error('Invalid Vault delegation response');
    }
    const auth = response && response.auth;
    if(!auth || typeof auth.client_token !== 'string' || !auth.client_token || auth.client_token === parent || !Number.isFinite(auth.lease_duration) || auth.lease_duration <= 0 || auth.lease_duration > ttl)
      throw new Error('Invalid Vault delegation response');
    cache = {token : auth.client_token, expires_at : createStarted + auth.lease_duration * 1000};
    if(!valid(cache, parent, Date.now()))
      throw new Error('Invalid Vault delegation TTL');
    this._delegates.set(key, cache);
    if(disk) {
      const temporary = file + '.' + randomUUID() + '.next';
      try {
        const armor = await encrypt(JSON.stringify(cache));
        fs.mkdirSync(path.dirname(file), {recursive : true, mode : 0o700});
        fs.writeFileSync(temporary, armor, {mode : 0o600, flag : 'wx'});
        fs.renameSync(temporary, file);
      } catch(err) {
        console.error('Could not encrypt/write delegation cache; token not persisted');
      } finally {
        try { fs.unlinkSync(temporary); } catch(err) {}
      }
    }
    if(!valid(cache, parent, Date.now()))
      throw new Error('Expired Vault delegation response');
    return cache.token;
  },
};
