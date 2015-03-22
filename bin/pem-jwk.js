#!/usr/bin/env node

var path = require('path')
var fs = require('fs')
var pj = require('../index')
var filename = process.argv[2]

if (!filename) {
  //TODO: use stdin
  console.error("Missing filename\nUsage:\n\tpem-jwk [filename]")
  process.exit(1)
}
var filepath = path.resolve(process.cwd(), filename)
try {
  var file = fs.readFileSync(filepath, 'utf8')
}
catch (e) {
  console.error('Could not read file: %s', filepath)
  process.exit(1)
}

if (file[0] === '{') {
  console.log(pj.jwk2pem(JSON.parse(file)))
}
else {
  console.log(pj.pem2jwk(file))
}
