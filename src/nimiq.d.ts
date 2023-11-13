import * as _Nimiq from '@nimiq/core-web/web';

export as namespace Nimiq;
export = _Nimiq;

declare global {
    const Nimiq: typeof _Nimiq;
}
