#!/usr/bin/env node
'use strict';

const cnyks  = require('cnyks/lib/bundle');
const Vvauth = require('../index');
const {args, dict} = require('nyks/process/parseArgs')();
const command = args.shift();
const options = command ? [`--ir://run=${command}`] : [];
if(command === 'env' && !dict['ir://json'])
  options.push('--ir://raw');

if(command === 'env' && dict.source) {
  (async () => {
    try {
      await new Vvauth().Env(dict.source, dict.renew, dict.gitlab);
    } catch(err) {
      // Fail the sourced helper, not the shell that called it.
      process.stdout.write('return 1\n');
      console.error(err, err && err.stack || '');
      process.exitCode = 1;
    }
  })();
} else {
  cnyks(Vvauth, 'vauth', options);
}
