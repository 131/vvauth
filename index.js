#!/usr/bin/env node
'use strict';

const os   = require('os');
const fs    = require('fs');
const path  = require('path');
const url   = require('url');
const {spawn, execFileSync} = require('child_process');
const passthru = require('nyks/child_process/passthru');
const wait     = require('nyks/child_process/wait');

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

        let {version} = require(require.resolve(`${module_name}/package.json`, {
          paths : ['.', ...require.main.paths]
        }));

        if(!semver.satisfies(version, module_version))
          throw `Unsupported ${module_name} version (requires ${module_version})`;
      }
    }

    this.rc = {};

    let vauth_rc = VAUTH_RC.filter(path => path && fs.existsSync(path))[0];
    if(vauth_rc) {
      let body = fs.readFileSync(vauth_rc, 'utf8');
      let rc = parse(body);
      let env = process.env;

      if(get(rc, 'env.gitlab') && !env.CI) {
        try {
          let remote_url = String(execFileSync('git', ['remote', 'get-url', 'origin'], {cwd : path.dirname(vauth_rc), stdio : ['ignore', 'pipe', 'ignore']})).trim();
          let match = remote_url.match(/^[^@]+@[^:]+:(.+)$/);
          let CI_PROJECT_PATH = match ? match[1] : trim(new URL(remote_url).pathname, '/');
          CI_PROJECT_PATH = trim(CI_PROJECT_PATH, '/').replace(/\.git$/, '');

          if(CI_PROJECT_PATH) {
            let parts = CI_PROJECT_PATH.split('/');
            let CI_PROJECT_NAME = parts.pop();
            let CI_PROJECT_NAMESPACE = parts.join('/');
            let CI_PROJECT_PATH_SLUG = String(CI_PROJECT_PATH).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');

            env = {...env, CI_PROJECT_PATH, CI_PROJECT_NAME, CI_PROJECT_NAMESPACE, CI_PROJECT_PATH_SLUG};
          }
        } catch(err) {}
      }

      this.rc = walk(rc, v =>  replaceEnv(v, {env}));
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
    let {profile, database} = await this._vault_get_profile();
    if(!profile.VAUTH_USER_LOGIN)
      throw "Could not resolve VAUTH_USER_LOGIN from vault identity";

    database[k.toUpperCase()] = v;
    await this._vault_write(`private/${profile.VAUTH_USER_LOGIN}`, '.vauth_database', database);
  }

  async unset(k) {
    await this.set(k, undefined);
  }

  async show() {
    let {profile, database} = await this._vault_get_profile();
    return {...database, ...profile};
  }

  async _vault_get_profile() {
    await this.connect();

    if(!this.VAULT_TOKEN)
      return {};

    let {entity_id} = await this._lookup_token(this.VAULT_TOKEN);
    let identity = await this._lookup_identity(this.VAULT_TOKEN, entity_id);
    let profile = {...(identity.metadata || {})};
    let database = {};

    if(profile.VAUTH_USER_LOGIN)
      database = await this._vault_read(`private/${profile.VAUTH_USER_LOGIN}`, '.vauth_database', true);

    return {entity_id, identity, profile, database};
  }

  async _get_env() {
    let {profile, database} = await this._vault_get_profile();
    profile = {...database, ...profile};

    let env = {VAULT_TOKEN : this.VAULT_TOKEN, VAULT_ADDR : this.VAULT_ADDR}, secrets = {},
      {git, map = {}, paths, path : mount = "secrets"} = this.rc.env || {};

    let {'ssh-agent-crypt' : agent } = this.rc;
    if(agent) {
      const {path, identity} = agent;
      let child = spawn('ssh-agent-crypt', ["-decrypt", identity]);

      child.stdin.end(fs.readFileSync(path));
      child.stderr.pipe(process.stderr);

      const [exit, body] = await Promise.all([wait(child, false), drain(child.stdout)]);
      if(exit !== 0) {
        console.error("Could not expand armored %s using %s", path, identity);
        process.exit();
      }
      const result = JSON.parse(body);
      secrets = {...secrets, ...result};
    }

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
        let data = await this._vault_read(mount, secret_path);
        secrets = {...secrets, ...data};
      }
    }
    for(let [k, v] of Object.entries(map))
      env[k] = replaceEnv(v, {env : process.env, profile, secrets});

    return env;
  }

  async dotenv() {
    const env = await this._get_env();

    for(let [k, v] of Object.entries(env)) {
      process.stdout.write(`${k}=${String(v)}\n`);
      process.stderr.write(`export ${k}=[redacted]\n`);
    }

    process.exit();
  }

  async env(source = false) {
    const env = await this._get_env();

    if(source) {
      this._publish_env(env);
      process.exit();
    }

    return env;
  }

  async _vault_read(mount, secret_path, optional = false) {
    let remote_url = `${trim(this.VAULT_ADDR, '/')}/v1/${mount}/data/${trim(secret_path, '/')}`;
    let query = {...url.parse(remote_url), headers : {'x-vault-token' : this.VAULT_TOKEN}};
    let res = await request(query);
    let body = String(await drain(res));

    if(optional && res.statusCode == 404)
      return {};

    if(res.statusCode != 200)
      throw `Could not read vault secret '${mount}/${trim(secret_path, '/')}' : ${body}`;

    return get(JSON.parse(body), 'data.data');
  }

  async _vault_write(mount, secret_path, data) {
    let remote_url = `${trim(this.VAULT_ADDR, '/')}/v1/${mount}/data/${trim(secret_path, '/')}`;
    let query = {...url.parse(remote_url), headers : {'x-vault-token' : this.VAULT_TOKEN}, json : true};
    let res = await request(query, {data});
    let body = String(await drain(res));

    if(res.statusCode != 200)
      throw `Could not write vault secret '${mount}/${trim(secret_path, '/')}' : ${body}`;

    return body ? JSON.parse(body) : {};
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
  // see man bash
  return "'" + String(arg).replace(/'/g, '\'"\'"\'') + "'";
};

//ensure module is called directly, i.e. not required
if(module.parent === null) {
  let cmd = args.shift();
  require('cnyks/lib/bundle')(vvauth, null, cmd ? [`--ir://run=${cmd}`, '--ir://raw'] : []);
}

module.exports = vvauth;
