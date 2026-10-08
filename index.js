#!/usr/bin/env node
'use strict';

const os   = require('os');
const fs    = require('fs');
const path  = require('path');
const url   = require('url');
const {createHash} = require('crypto');
const {encrypt, decrypt} = require('ssh-agent-crypt');
const {spawn, execFileSync} = require('child_process');
const passthru = require('nyks/child_process/passthru');
const wait     = require('nyks/child_process/wait');
const boolPrompt = require('cnyks/prompt/bool');

const {parse} = require('yaml');
const semver     = require('semver');
const trim       = require('mout/string/trim');
const get        = require('mout/object/get');
const eachLimit = require('nyks/async/eachLimit');
const walk       = require('nyks/object/walk');
const humanDiff  = require('nyks/date/humanDiff');

const request    = require('nyks/http/request');
const drain      = require('nyks/stream/drain');
const replaceEnv = require('nyks/string/replaceEnv');
const promiser   = require('nyks/function/promiser');
const {args} = require('nyks/process/parseArgs')();


const {createAgent} = require('ssh2/lib/agent');
const debug = require('debug');

const logger  = {
  debug : debug('vvauth:debug'),
  info  : debug('vvauth:info'),
  error : debug('vvauth:error'),
};


const VAUTH_RC = [process.env.VAUTHRC, path.join(process.cwd(), ".vauthrc"), path.join(os.homedir(), ".vauthrc")];
const FUNCTION_NAME = "venv";
const FUNCTION_DECL = `function ${FUNCTION_NAME}() { source <(/usr/bin/env vauth env --source "$@"); }`;

class vvauth {
  constructor() {


    let manifest = path.resolve('package.json');
    if(fs.existsSync(manifest)) {
      let {dependencies = {}} = require(path.resolve('package.json'));

      for(let [module_name, module_version]  of Object.entries(dependencies)) {

        let {version} = require(require.resolve(`${module_name}/package.json`, {
          paths : ['.', ...(require.main && require.main.paths || module.paths)]
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


    if(!process.env.SSH_AUTH_SOCK)
      this.rc.token_cache = false;

    this.VAULT_ADDR = this.rc.vault_addr || process.env.VAULT_ADDR; //might be null
    this.VAULT_TOKEN = process.env.VAULT_TOKEN;

    if(!this.VAULT_ADDR)
      console.error("Not bound to any vault");

  }

  async run() {
    let args = process.argv.slice(process.argv.indexOf("run") + 1);
    let env = await this.env(), cmd = args.shift();
    await passthru(cmd, args, {env : {...process.env, ...env}}).catch((err) => (console.error("run failure : ", err), process.exit(1)));
    process.exit();
  }

  _token_cache_key() {
    const {ssh_auth, jwt_auth} = this.rc;
    return createHash('sha256').update(JSON.stringify({
      vault_addr : trim(this.VAULT_ADDR || '', '/'), ssh_auth, jwt_auth,
    })).digest('hex');
  }

  _token_cache_file() {
    return path.join(os.homedir(), '.vauth', 'tokens', this._token_cache_key() + '.creds');
  }

  async _read_token_cache() {
    if(this.rc.token_cache === false)
      return;
    try {
      const armor = fs.readFileSync(this._token_cache_file(), 'utf8');
      return JSON.parse(await decrypt(armor));
    } catch(err) {}
  }

  async _save_cached_token(token, metadata) {
    if(this.rc.token_cache === false)
      return;
    const ttl = metadata.ttl === undefined ? metadata.lease_duration : metadata.ttl;
    const file = this._token_cache_file();
    const temporary = file + '.next';
    try {
      const {lease_duration} = metadata;
      const cache = {
        token, lease_duration, renewable : metadata.renewable === true,
        expires_at : ttl === 0 ? null : Date.now() + ttl * 1000,
      };
      fs.mkdirSync(path.dirname(file), {recursive : true, mode : 0o700});
      const identity = process.env.VAUTH_USER_IDENTITY || process.env.VAUTH_USER_MAIL;
      const armor = await encrypt(JSON.stringify(cache), identity);
      fs.writeFileSync(temporary, armor, {mode : 0o600});
      fs.renameSync(temporary, file);
    } catch(err) {
      // Cache failures must not prevent authentication or expose credentials.
      console.error('Could not encrypt/write token cache; token not persisted');
    } finally {
      try { fs.unlinkSync(temporary); } catch(err) {}
    }
  }

  _token_status(operation, metadata) {
    const ttl = metadata.ttl === undefined ? metadata.lease_duration : metadata.ttl;
    const validity = ttl === 0 ? 'valid indefinitely' : humanDiff(ttl, 2);
    console.error('Vauth token: %s · %s · %s', operation, this.VAULT_ADDR, validity);
  }

  async connect(renew = false) {
    if(this._connected && !renew)
      return this.VAULT_TOKEN;
    this._connected = false;

    const cached = await this._read_token_cache();
    let token = this.VAULT_TOKEN || (cached && cached.token);
    const had_token = !!token;
    let metadata, operation = 'reused';
    if(renew || (cached && token === cached.token && cached.expires_at !== null && cached.expires_at <= Date.now()))
      token = undefined;

    if(token) {
      try {
        if(cached && cached.token === token) {
          const ttl = cached.expires_at === null ? 0 : (cached.expires_at - Date.now()) / 1000;
          metadata = {...cached, ttl};
        } else {
          metadata = await this._lookup_token(token);
        }
        const {ttl, renewable, lease_duration} = metadata;
        if(ttl > 0 && ttl <= lease_duration / 3) {
          if(renewable) {
            metadata = await this._renew_token(token);
            token = metadata.client_token;
            operation = 'renewed';
          } else {
            token = undefined;
          }
        }
      } catch(err) {
        // Reauthenticate on invalid tokens, not network/server failures.
        const status = err.res && err.res.statusCode;
        if(![400, 403].includes(status))
          throw err;
        token = undefined;
      }
    }

    if(!token) {
      const {ssh_auth, jwt_auth} = this.rc;
      const agent_path = process.env.SSH_AUTH_SOCK || (process.platform === 'win32' ? 'pageant' : null);
      if(ssh_auth && agent_path) {
        metadata = await this._login_vault_ssh({...ssh_auth}, agent_path);
      } else if(jwt_auth && jwt_auth.jwt) {
        const {path, jwt, role} = jwt_auth;
        metadata = await this._login_vault(path, {jwt, role});
      }
      token = metadata && metadata.client_token;
      if(!token && (renew || had_token))
        throw new Error('Could not login to vault: no authentication method available');
      operation = 'generated';
    }

    if(token) {
      if(operation !== 'reused' || !cached || cached.token !== token)
        await this._save_cached_token(token, metadata);
      this._token_status(operation, metadata);
    }
    this.VAULT_TOKEN = token;
    this._connected = true;
    return token;
  }

  async _renew_token(token) {
    const remote_url = `${trim(this.VAULT_ADDR, '/')}/v1/auth/token/renew-self`;
    const query = {...url.parse(remote_url), headers : {'x-vault-token' : token}, expect : 200, json : true};
    const res = await request(query, {});
    const auth = JSON.parse(String(await drain(res))).auth;
    if(!auth.client_token || !Number.isFinite(auth.lease_duration) || auth.lease_duration < 0)
      throw new Error('Invalid Vault token renewal response');
    return auth;
  }

  async login(source = false, renew = false) {
    await this.connect(renew);
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

  async _vault_get_profile(renew = false) {
    await this.connect(renew);

    if(!this.VAULT_TOKEN)
      return {};

    let {entity_id} = await this._lookup_token(this.VAULT_TOKEN);
    let identity = await this._lookup_identity(this.VAULT_TOKEN, entity_id);
    let profile = {...(identity.metadata)};
    let database = {};

    if(profile.VAUTH_USER_LOGIN)
      database = await this._vault_read(`private/${profile.VAUTH_USER_LOGIN}`, '.vauth_database', true);

    return {entity_id, identity, profile, database};
  }

  async _get_env(renew = false) {
    let {profile, database} = await this._vault_get_profile(renew);
    profile = {...database, ...profile};

    let env = {}, secrets = {},
      {git, map = {}, paths, path : mount = "secrets"} = this.rc.env || {};

    if(this.VAULT_TOKEN)
      env.VAULT_TOKEN = this.VAULT_TOKEN;
    if(this.VAULT_ADDR)
      env.VAULT_ADDR = this.VAULT_ADDR;


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

  async env(source = false, renew = false) {
    const env = await this._get_env(renew);

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


  async _login_vault_ssh({path = 'ssh', role}, agent_path = process.env.SSH_AUTH_SOCK) {
    logger.info("Trying to auth as '%s'", role);

    let agent = createAgent(agent_path);
    let keys = await promiser(chain => agent.getIdentities(chain));


    let auth;
    await eachLimit(keys, 1, async (pubKey) => {
      if(auth)
        return;

      let remote_url = `${trim(this.VAULT_ADDR, '/')}/v1/auth/${path}/nonce`;
      let query = {...url.parse(remote_url), json : true};
      let res = await request(query);
      let {data : {nonce}} = JSON.parse(String(await drain(res)));

      const signature =  (await promiser(chain => agent.sign(pubKey, Buffer.from(nonce), {}, chain))).toString('base64');
      const public_key = pubKey.type + ' ' + pubKey.getPublicSSH().toString('base64');
      const payload = {public_key, role, nonce : Buffer.from(nonce).toString('base64'), signature};
      try {
        auth = await this._login_vault(path, payload);
      } catch(err) {
        logger.debug("ssh : invalid challenge for public key", pubKey.comment);
      }
    });


    if(!auth || !auth.client_token)
      throw `Could not login to vault`;

    return auth;
  }
  async _function_exists(alias) {
    let child = spawn('bash', ["-lc", `declare -F ${alias}`]);
    return new Promise(resolve => child.on('exit', resolve));
  }

  async install() {
    const bashrc_path = path.resolve(os.homedir(), ".bashrc");
    let bashrc = fs.existsSync(bashrc_path) ? fs.readFileSync(bashrc_path, 'utf-8').trim() : '';
    if(await this._function_exists(FUNCTION_NAME) === 0) {
      if(!await boolPrompt("Function already defined, override current definition? ", false))
        return;
    }
    console.error("Installing function %s in %s", FUNCTION_NAME, bashrc_path);

    fs.writeFileSync(bashrc_path, [bashrc, FUNCTION_DECL, ""].join("\n"));
    console.error(`Installation ok, please \nsource ${bashrc_path}`);
  }

  async _lookup_token(token) {
    let remote_url = `${trim(this.VAULT_ADDR, '/')}/v1/auth/token/lookup-self`;
    let query = {...url.parse(remote_url), headers : {'x-vault-token' : token}, expect : 200};
    let res = await request(query);
    let response = JSON.parse(await drain(res)).data;
    if(!Number.isFinite(response.ttl) || response.ttl < 0)
      throw new Error('Invalid Vault token TTL');
    const cached = await this._read_token_cache();
    if(cached && cached.token === token)
      response.lease_duration = cached.lease_duration;
    else
      response.lease_duration = response.creation_ttl;
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

    const auth = JSON.parse(response).auth;
    if(!auth.client_token || !Number.isFinite(auth.lease_duration) || auth.lease_duration < 0)
      throw new Error('Invalid Vault login response');
    return auth;
  }

}

const shellEscape = (arg) =>  {
  // see man bash
  return "'" + String(arg).replace(/'/g, '\'"\'"\'') + "'";
};

//ensure module is called directly, i.e. not required
if(module.parent === null) {
  let cmd = args.shift();
  const output = process.argv.includes('--ir://json') ? '--ir://json' : '--ir://raw';
  require('cnyks/lib/bundle')(vvauth, null, cmd ? [`--ir://run=${cmd}`, output] : []);
}

module.exports = vvauth;
