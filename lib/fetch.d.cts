/*!
 * client-certificate-auth/fetch - CommonJS type declarations
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import type * as FetchModule from './fetch.js';

declare const fetchAdapter: {
    load(): Promise<typeof FetchModule>;
};

export = fetchAdapter;
