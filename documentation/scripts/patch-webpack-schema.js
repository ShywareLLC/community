#!/usr/bin/env node
// Patches webpack's ProgressPlugin schema to accept webpackbar's options
// (name, color, reporters, reporter). Needed for Docusaurus 3.6.x + Node 22+.
const path = require('path');
const fs = require('fs');

const schemaPath = path.join(__dirname, '..', 'node_modules', 'webpack', 'schemas', 'plugins', 'ProgressPlugin.json');

if (!fs.existsSync(schemaPath)) {
  console.log('webpack schema not found — skipping patch');
  process.exit(0);
}

const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
const opts = schema.definitions?.ProgressPluginOptions;

if (!opts) {
  console.log('ProgressPluginOptions not found in schema — skipping patch');
  process.exit(0);
}

opts.additionalProperties = true;
fs.writeFileSync(schemaPath, JSON.stringify(schema, null, 2));
console.log('webpack ProgressPlugin schema patched (additionalProperties: true)');
