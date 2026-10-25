#!/usr/bin/env node
'use strict';

const os   = require('os');
const fs    = require('fs');
const path  = require('path');
const {decrypt} = require('ssh-agent-crypt');
const VauthLogin = require('vauth-login');
const {spawn} = require('child_process');
const exec = require('nyks/child_process/exec');
const parseArgs = require('nyks/process/parseArgs');
const readline = require('readline');

const semver     = require('semver');
const trim       = require('mout/string/trim');
const get        = require('mout/object/get');
const isPrimitive = require('mout/lang/isPrimitive');
const walk       = require('nyks/object/walk');
const structuredClone = require('nyks/object/structuredClone');

const replaceEnv = require('nyks/string/replaceEnv');


const {name : PACKAGE_NAME, version : VERSION} = require('./package.json');
const FUNCTION_NAME = "venv";
const FUNCTION_DECL = `function ${FUNCTION_NAME}() { source <(/usr/bin/env vauth env --source "$@"); }`;

class Vvauth extends VauthLogin {
  constructor() {


    // A project may pin the vauth it expects: `"dependencies": {"vvauth": "^2.5.0"}`.
    // Only vvauth itself is checked, against the running version.
    let manifest = path.resolve('package.json');
    if(fs.existsSync(manifest)) {
      const {dependencies = {}} = JSON.parse(fs.readFileSync(manifest, 'utf8'));
      const required = dependencies[PACKAGE_NAME];
      if(required && !semver.satisfies(VERSION, required))
        throw `Unsupported ${PACKAGE_NAME} version ${VERSION} (project requires ${required})`;
    }

    super();

    const rc = this.RC;
    const config = Object.fromEntries(['env', 'ssh-agent-crypt'].filter(key => rc && Object.hasOwn(rc, key)).map(key => [key, rc[key]]));
    this.config = walk(structuredClone(config), v => replaceEnv(v, {env : process.env}));
    if(this.config.env && this.config.env.gitlab === true) {
      const {args, dict} = parseArgs();
      const missing = ['CI_PROJECT_PATH', 'CI_PROJECT_NAME', 'CI_PROJECT_NAMESPACE', 'CI_PROJECT_PATH_SLUG'].filter(key => !process.env[key]);
      if(!(dict.gitlab || args[0] === 'gitlab') && missing.length)
        throw new Error(`Missing ${missing.join(', ')}. Run venv --gitlab first.`);
    }


    if(!this.VAULT_ADDR)
      console.error("Not bound to any vault");

  }

  static Version() /**
   * @alias version
   */ {
    return VERSION;
  }

  async Gitlab() /**
   * @alias gitlab
   */ {
    const remote = String(await exec('git', ['remote', 'get-url', 'origin'], {stdio : ['ignore', 'pipe', 'ignore']})).trim();
    const match = remote.includes('://') ? null : remote.match(/^[^@]+@[^:]+:(.+)$/);
    const project = trim(match ? match[1] : decodeURIComponent(new URL(remote).pathname), '/').replace(/\.git$/, '');
    if(!project)
      throw new Error('Could not resolve the Git project from origin');
    const parts = project.split('/');
    const variables = {
      CI_PROJECT_PATH : project,
      CI_PROJECT_NAME : parts.pop(),
      CI_PROJECT_NAMESPACE : parts.join('/'),
      CI_PROJECT_PATH_SLUG : project.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, ''),
    };
    this.PublishEnv(variables);
  }

  async Login(source = false, renew = false) /**
   * @alias login
   */ {
    await this.Connect(renew);
    if(source) {
      let env = {VAULT_TOKEN : this.VAULT_TOKEN || ''};
      this.PublishEnv(env);
    }
  }

  PublishEnv(env) {
    let cmds = [];
    for(let [k, v] of Object.entries(env)) {
      cmds.push(`export ${k}=${shellEscape(v)}`);
      cmds.push(`echo export ${k}="[redacted]" >&2`);
    }
    process.stdout.write(cmds.join("\n") + "\n");
  }


  async Set(k, v) /**
   * @alias set
   */ {
    let {profile, database} = await this.GetProfile();
    if(!profile.VAUTH_USER_LOGIN)
      throw "Could not resolve VAUTH_USER_LOGIN from vault identity";

    database[k.toUpperCase()] = v;
    await this._vault_write(`private/${profile.VAUTH_USER_LOGIN}`, '.vauth_database', database);
  }

  async Unset(k) /**
   * @alias unset
   */ {
    await this.Set(k, undefined);
  }

  async Show() /**
   * @alias show
   */ {
    let {profile, database} = await this.GetProfile();
    return {...database, ...profile};
  }

  async GetProfile(renew = false) {
    await this.Connect(renew);

    if(!this.VAULT_TOKEN || !this.VAULT_ADDR)
      return {profile : {}, database : {}};

    const {entity_id} = await this.LookupSelf(this.VAULT_TOKEN);
    const {body} = await this.Request('GET', `identity/entity/id/${entity_id}`, this.VAULT_TOKEN);
    const identity = JSON.parse(body).data;
    let profile = {...(identity.metadata)};
    let database = {};

    if(profile.VAUTH_USER_LOGIN)
      database = await this._vault_read(`private/${profile.VAUTH_USER_LOGIN}`, '.vauth_database', true);

    return {entity_id, identity, profile, database};
  }

  async Env(source = false, renew = false, gitlab = false) /**
   * @alias env
   */ {
    if(gitlab) {
      await this.Gitlab();
      return;
    }
    let env = {}, secrets = {}, profile = {};
    let {git, map = {}, paths, path : mount = "secrets"} = this.config.env || {};
    const localCredentials = this.config['ssh-agent-crypt'] && !this.RC.ssh_auth && !this.RC.jwt_auth;
    if(localCredentials) {
      await this.Connect(renew);
    } else {
      const current = await this.GetProfile(renew);
      profile = {...current.database, ...current.profile};
    }

    if(this.VAULT_TOKEN)
      env.VAULT_TOKEN = this.VAULT_TOKEN;
    if(this.VAULT_ADDR)
      env.VAULT_ADDR = this.VAULT_ADDR;


    let {'ssh-agent-crypt' : agent } = this.config;
    if(agent) {
      const {path, identity} = agent;
      const body = await decrypt(fs.readFileSync(path), identity);
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
    for(let [k, v] of Object.entries(map)) {
      // the key reaches `export KEY=...` unescaped; .vauthrc may come from an untrusted working directory
      if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k))
        throw new Error(`Invalid environment variable name '${k}' in env.map`);
      env[k] = envValue(replaceEnv(envValue(v, k), {env : process.env, profile, secrets}), k);
    }

    if(source) {
      this.PublishEnv(env);
      return;
    }
    return env;
  }

  async Dotenv() /**
   * @alias dotenv
   */ {
    const env = await this.Env();

    for(let [k, v] of Object.entries(env)) {
      process.stdout.write(`${k}=${String(v)}\n`);
      process.stderr.write(`export ${k}=[redacted]\n`);
    }

  }

  async _vault_read(mount, secret_path, optional = false) {
    const {status, body} = await this.Request('GET', `${mount}/data/${trim(secret_path, '/')}`, this.VAULT_TOKEN, null, 0);
    if(optional && status === 404)
      return {};
    if(status !== 200)
      throw new VauthLogin.HTTPError(status, body.toString());
    return get(JSON.parse(body), 'data.data');
  }

  async _vault_write(mount, secret_path, data) {
    const {body} = await this.Request('POST', `${mount}/data/${trim(secret_path, '/')}`, this.VAULT_TOKEN, {data}, 200);
    return body.length ? JSON.parse(body) : {};
  }

  async _function_exists(alias) {
    let child = spawn('bash', ["-lc", `declare -F ${alias}`]);
    return new Promise(resolve => child.on('exit', resolve));
  }

  async Install() /**
   * @alias install
   */ {
    const bashrc_path = path.resolve(os.homedir(), ".bashrc");
    let bashrc = fs.existsSync(bashrc_path) ? fs.readFileSync(bashrc_path, 'utf-8').trim() : '';
    if(await this._function_exists(FUNCTION_NAME) === 0) {
      const prompt = readline.createInterface({input : process.stdin, output : process.stdout});
      const answer = await new Promise(resolve => {
        prompt.once('close', () => resolve(''));
        prompt.question('Function already defined, override current definition?  [y/N] ', value => { resolve(value); prompt.close(); });
      });
      if(!/^y(es)?$/i.test(answer.trim())) return;
    }
    console.error("Installing function %s in %s", FUNCTION_NAME, bashrc_path);

    fs.writeFileSync(bashrc_path, [bashrc, FUNCTION_DECL, ""].join("\n"));
    console.error(`Installation ok, please \nsource ${bashrc_path}`);
  }


}

const envValue = (value, key) => {
  if(value == null)
    return '';
  if(!isPrimitive(value) || (typeof value === 'number' && !Number.isFinite(value)))
    throw new Error(`Invalid environment value '${key}' in env.map: expected a scalar`);
  return String(value);
};

const shellEscape = (arg) =>  {
  // see man bash
  return "'" + String(arg).replace(/'/g, '\'"\'"\'') + "'";
};

module.exports = Vvauth;
