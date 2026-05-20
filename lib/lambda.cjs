/*!
 * client-certificate-auth/lambda - CommonJS wrapper
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

'use strict';

let _module;

async function load() {
    // Stryker disable next-line ConditionalExpression,BlockStatement: test ordering caches _module from prior test; ConditionalExpression→true (always re-import) re-imports same module successfully; BlockStatement→{} uses cached value
    if (!_module) {
        // Stryker disable next-line StringLiteral: test ordering caches _module; StringLiteral→"" fails import but cached value masks it
        _module = await import('./lambda.js');
    }
    return _module;
}

module.exports = { load };
