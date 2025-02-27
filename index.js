#!/usr/bin/env node
'use strict';

const fs    = require('fs');
const path  = require('path');
const url   = require('url');
const net   = require('net');


const {parse} = require('yaml');
const {args} = require('nyks/process/parseArgs')();
const deepMixIn  = require('mout/object/deepMixIn');
const SSHAgent   = require('ssh-agent-js/client');
const trim       = require('mout/string/trim');
const get        = require('mout/object/get');
const eachLimit = require('nyks/async/eachLimit');

const request    = require('nyks/http/request');
const drain      = require('nyks/stream/drain');

const debug = require('debug');

const logger  = {
  debug : debug('dspp:secrets:debug'),
  info  : debug('dspp:secrets:info'),
  error : debug('dspp:secrets:error'),
};


const VCREDS_RC = ".vcredsrc";

class vcreds {
  constructor() {
    this.rc = {};
    if(fs.existsSync(VCREDS_RC)) {
      let body = fs.readFileSync(VCREDS_RC, 'utf8');
      this.rc = parse(body);
    }
  }

  async login() {
    let {vault_addr, ssh_auth, jwt_auth} = this.rc;

    let token = this.rc.VAULT_TOKEN;
    if(!token && ssh_auth && process.env.SSH_AUTH_SOCK)
      token = await this._login_vault_ssh({...ssh_auth, vault_addr});


    if(!token && jwt_auth && jwt_auth.jwt) {
      let {path, jwt, role} = jwt_auth, payload = {jwt, role};
      token = await this._login_vault(vault_addr, path, payload);
    }

    console.log({token})
  }

  async _login_vault_ssh({vault_addr, path = 'ssh', role}) {
    let sock;
    await new Promise(resolve => (sock = net.connect(process.env.SSH_AUTH_SOCK, resolve)));
    let agent = new SSHAgent(sock);
    let keys = Object.values(await agent.list_keys());

    let token;
    await eachLimit(keys, 1, async ({type, ssh_key, fingerprint, comment}) => {
      if(token)
        return;

      let remote_url = `${trim(vault_addr, '/')}/v1/auth/${path}/nonce`;
      let query = {...url.parse(remote_url), json : true};
      let res = await request(query);
      let {data : {nonce}} = JSON.parse(String(await drain(res)));

      const public_key = `${type} ${ssh_key}`;
      const {signature} =  await agent.sign(fingerprint, Buffer.from(nonce));

      const payload = {public_key, role, nonce : Buffer.from(nonce).toString('base64'), signature};
      try {
        token = await this._login_vault(vault_addr, path, payload);
      } catch(err) {
        logger.debug("ssh : invalid challenge for public key", comment);
      }
    });

    sock.destroy();

    if(!token)
      throw `Could not login to vault`;

    return token;
  }

  async _login_vault(vault_addr, path, payload) {
    let remote_url = `${trim(vault_addr, '/')}/v1/auth/${path}/login`;
    let query = {...url.parse(remote_url), json : true};
    let res = await request(query, payload);
    let response = String(await drain(res));

    if(res.statusCode !== 200)
      throw `Could not login to vault : ${response}`;

    response = JSON.parse(response);
    console.log(response);
    let token = get(response, 'auth.client_token');
    return token;
  }


  async _process_vault({vault_addr, secret_path, jwt_auth, ssh_auth}) {


  }


}

//ensure module is called directly, i.e. not required
if(module.parent === null) {
  let cmd = args.shift();
  require('cnyks/lib/bundle')(vcreds, null, [`--ir://run=${cmd}`]); //start runner
}


module.exports = vcreds;
