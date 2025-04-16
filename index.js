#!/usr/bin/env node
'use strict';

const os   = require('os');
const fs    = require('fs');
const path  = require('path');
const url   = require('url');
const {spawn} = require('child_process');
const passthru = require('nyks/child_process/passthru');

const {parse} = require('yaml');
const semver     = require('semver');
const trim       = require('mout/string/trim');
const get        = require('mout/object/get');
const eachLimit = require('nyks/async/eachLimit');
const walk       = require('nyks/object/walk');

const request    = require('nyks/http/request');
const drain      = require('nyks/stream/drain');
const replaceEnv = require('nyks/string/replaceEnv');
const promiser   = require('nyks/function/promiser');
const {args} = require('nyks/process/parseArgs')();


const {OpenSSHAgent} = require('ssh2/lib/agent');
const debug = require('debug');

const logger  = {
  debug : debug('vvauth:debug'),
  info  : debug('vvauth:info'),
  error : debug('vvauth:error'),
};


const VAUTH_RC = [process.env.VAUTHRC, path.join(process.cwd(), ".vauthrc"), path.join(os.homedir(), ".vauthrc")];
const FUNCTION_NAME = "venv";
const FUNCTION_DECL = `function ${FUNCTION_NAME}() { source <(/usr/bin/env vauth env --source); }`;

class vvauth {
  constructor() {


    let manifest = path.resolve('package.json');
    if(fs.existsSync(manifest)) {
      let {dependencies = {}} = require(path.resolve('package.json'));
      for(let [module_name, module_version]  of Object.entries(dependencies)) {
        let {version} = require(require.resolve(`${module_name}/package.json`));
        if(!semver.satisfies(version, module_version))
          throw `Unsupported ${module_name} version (requires ${module_version})`;
      }
    }

    this.rc = {};

    let vauth_rc = VAUTH_RC.filter(path => path && fs.existsSync(path))[0];
    if(vauth_rc) {
      let body = fs.readFileSync(vauth_rc, 'utf8');
      this.rc = walk(parse(body), v =>  replaceEnv(v, {env : process.env}));
    }

    this.VAULT_ADDR = this.rc.vault_addr;

    if(!this.VAULT_ADDR)
      throw `Invalid vault remote`;

    this.VAULT_TOKEN = process.env.VAULT_TOKEN;
    console.error("vauth bound to '%s'", this.VAULT_ADDR);
  }

  async run() {
    let args = process.argv.slice(process.argv.indexOf("run") + 1);
    let env = await this.env(), cmd = args.shift();
    await passthru(cmd, args, {env : {...process.env, ...env}}).catch((err) => (console.error("run failure : ", err), process.exit(1)));
    process.exit();
  }

  async connect() {
    let VAULT_TOKEN, {rc : {ssh_auth, jwt_auth}} = this;

    if(!VAULT_TOKEN && ssh_auth && process.env.SSH_AUTH_SOCK)
      VAULT_TOKEN = await this._login_vault_ssh({...ssh_auth});

    if(!VAULT_TOKEN && jwt_auth && jwt_auth.jwt) {
      let {path, jwt, role} = jwt_auth, payload = {jwt, role};
      VAULT_TOKEN = await this._login_vault(path, payload);
    }
    this.VAULT_TOKEN = VAULT_TOKEN;
  }

  async login(source = false) {
    await this.connect();
    if(source) {
      let env = {VAULT_TOKEN : this.VAULT_TOKEN};
      this._publish_env(env);
      process.exit();
    }
  }

  _publish_env(env) {
    let cmds = [];
    for(let [k, v] of Object.entries(env)) {
      cmds.push(`export ${k}=${shellEscape(v)}`);
      cmds.push(`echo export ${k}="[redacted]" >&2`);
    }
    process.stdout.write(cmds.join("\n") + "\n");
  }


  async set(k, v) {
    let {entity_id, identity : {metadata}} = await this._get_profile();
    if(!metadata)
      metadata = {};
    let key_name = `env_${k.toUpperCase()}`;
    metadata[key_name] = v;
    await this._update_identity(this.VAULT_TOKEN, entity_id, {metadata});
  }

  async unset(k) {
    await this.set(k, undefined);
  }

  async show() {
    let {profile} = await this._get_profile();
    return profile;
  }

  async _get_profile() {
    await this.connect();
    let {entity_id} = await this._lookup_token(this.VAULT_TOKEN);
    let identity = await this._lookup_identity(this.VAULT_TOKEN, entity_id);
    let profile = {};
    for(let alias of identity.aliases) {
      for(let [k, v] of Object.entries(alias.custom_metadata || {})) {
        if(k.startsWith('env_'))
          profile[k.substr(4)] = v;
      }
    }
    for(let [k, v] of Object.entries(identity.metadata || {})) {
      if(k.startsWith('env_'))
        profile[k.substr(4)] = v;
    }
    return {entity_id, identity, profile};
  }

  async env(source = false) {
    let {profile} = await this._get_profile();

    let env = {VAULT_TOKEN : this.VAULT_TOKEN, VAULT_ADDR : this.VAULT_ADDR}, secrets = {},
      {git, map = {}, paths, path : mount = "secrets"} = this.rc.env || {};

    if(git) {
      map = {...map,
        "GIT_COMMITTER_NAME" : profile.VAUTH_USER_NAME,
        "GIT_COMMITTER_EMAIL" : profile.VAUTH_USER_MAIL,
        "GIT_AUTHOR_EMAIL" : profile.VAUTH_USER_MAIL,
        "GIT_AUTHOR_NAME" : profile.VAUTH_USER_NAME,
        "GIT_USER_LOGIN" : profile.VAUTH_USER_LOGIN,
      };
    }
    if(paths) {
      for(let secret_path of paths) {
        console.error("reaching paths", secret_path);
        let data = await this._read(mount, secret_path);
        secrets = {...secrets, ...data};
      }
    }
    for(let [k, v] of Object.entries(map))
      env[k] = replaceEnv(v, {env : process.env, profile, secrets});

    if(source) {
      this._publish_env(env);
      process.exit();
    }
    return env;
  }


  async _read(mount, secret_path) {
    let remote_url = `${trim(this.VAULT_ADDR, '/')}/v1/${mount}/data/${trim(secret_path, '/')}`;
    let query = {...url.parse(remote_url), headers : {'x-vault-token' : this.VAULT_TOKEN}, expect : 200};
    let res = await request(query);
    return get(JSON.parse(String(await drain(res))), 'data.data');
  }

  async _login_vault_ssh({path = 'ssh', role}) {
    logger.info("Trying to auth as '%s'", role);


    let agent = new OpenSSHAgent(process.env.SSH_AUTH_SOCK);
    let keys = await promiser(chain => agent.getIdentities(chain));


    let token;
    await eachLimit(keys, 1, async (pubKey) => {
      if(token)
        return;

      let remote_url = `${trim(this.VAULT_ADDR, '/')}/v1/auth/${path}/nonce`;
      let query = {...url.parse(remote_url), json : true};
      let res = await request(query);
      let {data : {nonce}} = JSON.parse(String(await drain(res)));

      const signature =  (await promiser(chain => agent.sign(pubKey, Buffer.from(nonce), {}, chain))).toString('base64');
      const public_key = pubKey.type + ' ' + pubKey.getPublicSSH().toString('base64');
      const payload = {public_key, role, nonce : Buffer.from(nonce).toString('base64'), signature};
      try {
        token = await this._login_vault(path, payload);
      } catch(err) {
        logger.debug("ssh : invalid challenge for public key", pubKey.comment);
      }
    });


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

  async _lookup_token(token) {
    let remote_url = `${trim(this.VAULT_ADDR, '/')}/v1/auth/token/lookup-self`;
    let query = {...url.parse(remote_url), headers : {'x-vault-token' : token}, expect : 200};
    let res = await request(query);
    let response = JSON.parse(await drain(res)).data;
    return response;
  }

  async _lookup_identity(token, id) {
    let remote_url = `${trim(this.VAULT_ADDR, '/')}/v1/identity/entity/id/${id}`;
    let query = {...url.parse(remote_url), headers : {'x-vault-token' : token}, expect : 200};
    let res = await request(query);
    return JSON.parse(String(await drain(res))).data;
  }

  async _update_identity(token, id, payload) {
    let remote_url = `${trim(this.VAULT_ADDR, '/')}/v1/identity/entity/id/${id}`;
    let query = {...url.parse(remote_url), headers : {'x-vault-token' : token}, expect : 204, json : true};
    await request(query, payload);
    return payload;
  }



  async _login_vault(path, payload) {
    let remote_url = `${trim(this.VAULT_ADDR, '/')}/v1/auth/${path}/login`;
    let query = {...url.parse(remote_url), json : true};
    let res = await request(query, payload);
    let response = String(await drain(res));

    if(res.statusCode !== 200)
      throw `Could not login to vault : ${response}`;

    response = JSON.parse(response);
    let token = get(response, 'auth.client_token');
    return token;
  }

}

const shellEscape = (arg) =>  {
  return String(arg).replace(/([$!'"();`*?{}[\]<>&%#~@\\ ])/g, '\\$1');
};

//ensure module is called directly, i.e. not required
if(module.parent === null) {
  let cmd = args.shift();
  require('cnyks/lib/bundle')(vvauth, null, cmd ? [`--ir://run=${cmd}`, '--ir://raw'] : []);
}

module.exports = vvauth;
