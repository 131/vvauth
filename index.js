#!/usr/bin/env node
'use strict';

const os   = require('os');
const fs    = require('fs');
const path  = require('path');
const url   = require('url');
const net   = require('net');
const {spawn} = require('child_process');

const {parse} = require('yaml');
const {args} = require('nyks/process/parseArgs')();
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

    let env = {
      VAULT_TOKEN : token
    };
    this._publish_env(env);
  }

  _publish_env(env) {
    let cmds = [];
    for(let [k, v] of Object.entries(env)) {
      cmds.push(`export ${k}=${v}`);
      cmds.push(`echo publishing ${k} : ok>&2`);
    }
    process.stdout.write(cmds.join("\n") + "\n");
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
  async _alias_exists(alias) {
    let child = spawn('bash', ["-lc", `alias ${alias}`]);
    return new Promise(resolve => child.on('exit', resolve));
  }

  async install() {
    const alias_name = "vauth";
    const alias_value = "source <(vcreds login)";
    const bashrc_path = path.resolve(os.homedir(), ".bashrc");
    let bashrc = fs.existsSync(bashrc_path) ? fs.readFileSync(bashrc_path, 'utf-8').trim() : '';
    let exists = await this._alias_exists(alias_name);
    if(exists == 0) {
      console.error("Alias %s already installed", alias_name);
      return;
    }
    console.error("Alias %s not installed, pushing it to %s", alias_name, bashrc_path);

    fs.writeFileSync(bashrc_path, [bashrc, `alias ${alias_name}="${alias_value}"`].join("\n"));
    console.error(`Installation ok, please \nsource ${bashrc_path}`);
  }

  async _login_vault(vault_addr, path, payload) {
    let remote_url = `${trim(vault_addr, '/')}/v1/auth/${path}/login`;
    let query = {...url.parse(remote_url), json : true};
    let res = await request(query, payload);
    let response = String(await drain(res));

    if(res.statusCode !== 200)
      throw `Could not login to vault : ${response}`;

    response = JSON.parse(response);
    //console.log(response);
    let token = get(response, 'auth.client_token');
    return token;
  }




}

//ensure module is called directly, i.e. not required
if(module.parent === null) {
  let cmd = args.shift();
  let run = cmd ? [`--ir://raw`, `--ir://run=${cmd}`] : [];
  require('cnyks/lib/bundle')(vcreds, null, run);
}


module.exports = vcreds;
