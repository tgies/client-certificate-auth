/**
 * Augment the global Error interface for Express/Connect middleware conventions.
 */
interface Error {
    /** HTTP status code for error responses */
    status?: number;
}
