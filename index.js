#!/usr/bin/env node
'use strict';

const os   = require('os');
const fs    = require('fs');
const path  = require('path');
const {decrypt} = require('ssh-agent-crypt');
const VauthLogin = require('vauth-login');
const parseArgs = require('nyks/process/parseArgs');
const {spawn, execFileSync} = require('child_process');
const readline = require('readline');

const {parse} = require('yaml');
const semver     = require('semver');
const trim       = require('mout/string/trim');
const get        = require('mout/object/get');
const walk       = require('nyks/object/walk');

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
    this.config = {};

    const vauth_rc = this.rc_file;
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

      const config = Object.fromEntries(['env', 'ssh-agent-crypt'].filter(key => rc && Object.hasOwn(rc, key)).map(key => [key, rc[key]]));
      this.config = walk(config, v => replaceEnv(v, {env}));
    }


    if(!this.VAULT_ADDR)
      console.error("Not bound to any vault");

  }

  static Version() {
    return VERSION;
  }

  async Run(command, ...args) {
    const env = await this.Env();
    const child = spawn(command, args, {env : {...process.env, ...env}, stdio : 'inherit'});
    return new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', resolve);
    });
  }

  async Login(source = false, renew = false) {
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


  async Set(k, v) {
    let {profile, database} = await this.GetProfile();
    if(!profile.VAUTH_USER_LOGIN)
      throw "Could not resolve VAUTH_USER_LOGIN from vault identity";

    database[k.toUpperCase()] = v;
    await this._vault_write(`private/${profile.VAUTH_USER_LOGIN}`, '.vauth_database', database);
  }

  async Unset(k) {
    await this.Set(k, undefined);
  }

  async Show() {
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

  async Env(source = false, renew = false) {
    let env = {}, secrets = {}, profile = {};
    let {git, map = {}, paths, path : mount = "secrets"} = this.config.env || {};
    const localCredentials = this.config['ssh-agent-crypt'] && !this.rc.ssh_auth && !this.rc.jwt_auth;
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
      env[k] = replaceEnv(v, {env : process.env, profile, secrets});
    }

    if(source) {
      this.PublishEnv(env);
      return;
    }
    return env;
  }

  async Dotenv() {
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

  async Install() {
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

const shellEscape = (arg) =>  {
  // see man bash
  return "'" + String(arg).replace(/'/g, '\'"\'"\'') + "'";
};

// Command spelling is a CLI concern, not an SDK compatibility alias.
async function main() {
  const argv = process.argv.slice(2);
  if(argv[0] === 'run') {
    const args = argv.slice(1);
    if(args[0] === '--') args.shift();
    const command = args.shift();
    if(!command) throw new Error('Missing command for run');
    process.exitCode = await new Vvauth().Run(command, ...args);
    return;
  }
  const {args, dict} = parseArgs(argv);
  const command = args.shift() || (dict.version ? 'version' : undefined);
  if(command === 'version') {
    process.stdout.write(Vvauth.Version() + '\n');
    return;
  }
  if(!['env', 'login', 'connect', 'dotenv', 'show', 'set', 'unset', 'install'].includes(command))
    throw new Error('Usage: vauth <env|login|connect|run|dotenv|show|set|unset|install|version>');
  if(Object.hasOwn(dict, 'ir://run'))
    throw new Error('Unsupported flag --ir://run');
  const param = (index, name) => index < args.length ? args[index] : dict[name];
  const enabled = value => value !== undefined && !['', 'false', '0'].includes(String(value).toLowerCase());
  const client = new Vvauth();
  let result;
  switch(command) {
    case 'env': result = await client.Env(enabled(param(0, 'source')), enabled(param(1, 'renew'))); break;
    case 'login': await client.Login(enabled(param(0, 'source')), enabled(param(1, 'renew'))); return;
    case 'connect': result = await client.Connect(enabled(param(0, 'renew'))); break;
    case 'dotenv': await client.Dotenv(); return;
    case 'show': result = await client.Show(); break;
    case 'set':
      if(param(0, 'k') === undefined || param(1, 'v') === undefined) throw new Error('Missing parameter --k or --v');
      await client.Set(param(0, 'k'), param(1, 'v')); return;
    case 'unset':
      if(param(0, 'k') === undefined) throw new Error('Missing parameter --k');
      await client.Unset(param(0, 'k')); return;
    case 'install': await client.Install(); return;
  }
  if(result !== undefined && result !== '') {
    if(Object.hasOwn(dict, 'ir://json') || typeof result !== 'string')
      process.stdout.write(JSON.stringify(result) + (Object.hasOwn(dict, 'ir://json') ? '' : '\n'));
    else
      process.stdout.write(result);
  }
}

if(require.main === module)
  main().catch(err => { console.error(err instanceof Error ? err.message : String(err)); process.exitCode = 1; });

module.exports = Vvauth;
