/*!
 * client-certificate-auth/helpers - CommonJS type declarations
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import type * as HelpersModule from './helpers.js';

declare const helpers: {
    load(): Promise<typeof HelpersModule>;
};

export = helpers;
