declare module "node:test" {
    export function test(name: string, fn: () => void | Promise<void>): void;
    export function describe(name: string, fn: () => void): void;
    export function before(fn: () => void | Promise<void>): void;
    export function after(fn: () => void | Promise<void>): void;
    export function beforeEach(fn: () => void | Promise<void>): void;
    export function afterEach(fn: () => void | Promise<void>): void;
}