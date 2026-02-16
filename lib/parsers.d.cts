/*!
 * client-certificate-auth/parsers - CommonJS type declarations
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import type * as ParsersModule from './parsers.js';

declare const parsers: {
    load(): Promise<typeof ParsersModule>;
};

export = parsers;
