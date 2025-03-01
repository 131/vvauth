#!/usr/bin/env node
'use strict';

const os   = require('os');
const fs    = require('fs');
const path  = require('path');
const url   = require('url');
const net   = require('net');
const {spawn} = require('child_process');

const {parse} = require('yaml');
const SSHAgent   = require('ssh-agent-js/client');
const trim       = require('mout/string/trim');
const get        = require('mout/object/get');
const eachLimit = require('nyks/async/eachLimit');
const walk       = require('nyks/object/walk');

const request    = require('nyks/http/request');
const drain      = require('nyks/stream/drain');
const replaceEnv = require('nyks/string/replaceEnv');

const debug = require('debug');

const logger  = {
  debug : debug('dspp:secrets:debug'),
  info  : debug('dspp:secrets:info'),
  error : debug('dspp:secrets:error'),
};


const VAUTH_RC = process.env.VAUTHRC || ".vauthrc";
const FUNCTION_NAME = "vauth";
const FUNCTION_DECL = "function vauth() { source <(/usr/bin/env vvauth --ir://raw --source --ir://run=$1 \"${@:2}\"); }";

class vvauth {
  constructor(rc = null) {
    this.rc = {};
    if(rc) {
      this.rc = rc;
    } else {
      if(fs.existsSync(VAUTH_RC)) {
        let body = fs.readFileSync(VAUTH_RC, 'utf8');
        this.rc = walk(parse(body), v =>  replaceEnv(v, { env : process.env}));
      }
    }

    let {vault_addr} = this.rc;
    if(!vault_addr)
      throw `Invalid vault remote`;
    console.error("vauth bound to '%s'", vault_addr);
  }

  async _get_token() {
    let {vault_addr, ssh_auth, jwt_auth} = this.rc;

    let token = this.rc.VAULT_TOKEN;
    if(!token && ssh_auth && process.env.SSH_AUTH_SOCK)
      token = await this._login_vault_ssh({...ssh_auth, vault_addr});

    if(!token && jwt_auth && jwt_auth.jwt) {
      let {path, jwt, role} = jwt_auth, payload = {jwt, role};
      token = await this._login_vault(vault_addr, path, payload);
    }
    return token;
  }

  async login(source = false) {

    let VAULT_TOKEN = await this._get_token();
    if(source) {
      let env = {VAULT_TOKEN};
      this._publish_env(env);
      process.exit();
    }
    return VAULT_TOKEN;
  }

  _publish_env(env) {
    let cmds = [];
    for(let [k, v] of Object.entries(env)) {
      cmds.push(`export ${k}=${v}`);
      cmds.push(`echo export ${k}=[redacted] >&2`);
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
  async _function_exists(alias) {
    let child = spawn('bash', ["-lc", `declare -F ${alias}`]);
    return new Promise(resolve => child.on('exit', resolve));
  }

  async install() {
    const bashrc_path = path.resolve(os.homedir(), ".bashrc");
    let bashrc = fs.existsSync(bashrc_path) ? fs.readFileSync(bashrc_path, 'utf-8').trim() : '';
    let exists = await this._function_exists(FUNCTION_NAME);
    if(exists == 0) {
      console.error("Function %s already installed", FUNCTION_NAME);
      return;
    }
    console.error("Alias %s not installed, pushing it to %s", FUNCTION_NAME, bashrc_path);

    fs.writeFileSync(bashrc_path, [bashrc, FUNCTION_DECL, ""].join("\n"));
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
if(module.parent === null)
  require('cnyks/lib/bundle')(vvauth);


module.exports = vvauth;
