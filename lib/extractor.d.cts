/*!
 * client-certificate-auth/extractor - CommonJS type declarations
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import type * as ExtractorModule from './extractor.js';

declare const extractor: {
    load(): Promise<typeof ExtractorModule>;
};

export = extractor;
