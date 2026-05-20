/*!
 * client-certificate-auth/lambda - CommonJS type declarations
 * Copyright (C) 2013-2026 Tony Gies
 * @license MIT
 */

import type * as LambdaModule from './lambda.js';

declare const lambda: {
    load(): Promise<typeof LambdaModule>;
};

export = lambda;
