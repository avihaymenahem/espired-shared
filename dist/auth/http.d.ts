export interface ErrorAnswer {
    status: number;
    message: string;
}
export declare function describeError(err: unknown): ErrorAnswer;
/** Default error hook: logs only server-side failures (5xx) so expected rejections stay quiet. */
export declare function defaultOnError(err: unknown): void;
export declare const ERROR_HEADERS: Readonly<Record<string, string>>;
