#!/usr/bin/env node
'use strict';

const cnyks  = require('cnyks/lib/bundle');
const Vvauth = require('../index');
const {args, dict} = require('nyks/process/parseArgs')();
const command = args.shift();
const options = command ? [`--ir://run=${command}`] : [];
if(command === 'env' && !dict['ir://json'])
  options.push('--ir://raw');

cnyks(Vvauth, 'vauth', options);
