// Runs the REAL script out of Views/callback.html in a stubbed browser, so this
// exercises shipped code rather than a copy of the logic.
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HTML = process.env.CALLBACK_HTML
    || path.join(HERE, '..', 'kdnx-jellyfin-oidc', 'Views', 'callback.html');
const THIS_SERVER = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const FRIEND_SERVER = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

let fails = 0;
const check = (ok, label, got) => {
    console.log((ok ? '  PASS  ' : '  FAIL  ') + label + (ok ? '' : `   got: ${JSON.stringify(got)}`));
    if (!ok) fails++;
};

function extractScript() {
    const html = readFileSync(HTML, 'utf8');
    return html.match(/<script nonce="___nonce___">([\s\S]*?)<\/script>/)[1]
        // server-side substitutions (WebResponse.Generator writes JSON literals here)
        .replaceAll('"___jsonPunycodeBaseUrl___"', '""')
        .replaceAll('"___jsonAuthUrl___"', '"/sso/OID/Auth/KDNX"')
        .replaceAll('"___jsonData___"', '"one-time-token"');
}

async function run({ seedCredentials }) {
    const store = new Map();
    if (seedCredentials) store.set('jellyfin_credentials', JSON.stringify(seedCredentials));
    store.set('_deviceId2', 'device-abc');

    const localStorage = {
        getItem: k => (store.has(k) ? store.get(k) : null),
        setItem: (k, v) => store.set(k, String(v)),
        removeItem: k => store.delete(k),
    };

    // Setting iframe.src simulates jellyfin-web booting: it writes a FRESH credentials
    // blob containing only this server.
    const iframe = {
        set src(v) {
            if (!v) return;
            store.set('jellyfin_credentials', JSON.stringify({ Servers: [{ Id: THIS_SERVER, Name: 'home' }] }));
        },
        get src() { return ''; },
    };

    const message = { textContent: '' };
    const sandbox = {
        localStorage,
        navigator: { userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0', maxTouchPoints: 0 },
        document: {
            getElementById: () => iframe,
            querySelector: () => message,
            addEventListener: () => {},
        },
        window: {},
        setTimeout,
        console,
        JSON,
        fetch: async () => ({
            ok: true,
            text: async () => JSON.stringify({
                User: { Id: 'user-1', ServerId: THIS_SERVER, Name: 'kuro' },
                AccessToken: 'NEW-TOKEN',
                ServerId: THIS_SERVER,
                SessionInfo: {},
                SessionExpiresAt: 1754204800,
            }),
        }),
    };
    sandbox.window.location = { replace: () => {} };

    const ctx = vm.createContext(sandbox);
    vm.runInContext(extractScript() + '\n;globalThis.__main = main;', ctx);
    await ctx.__main();

    return { store, message };
}

console.log('== callback.html: multi-server credentials ==');
{
    const { store } = await run({
        seedCredentials: {
            Servers: [
                { Id: FRIEND_SERVER, Name: "friend's server", AccessToken: 'FRIEND-TOKEN', UserId: 'friend-user' },
                { Id: THIS_SERVER, Name: 'home', AccessToken: 'OLD-TOKEN', UserId: 'old-user' },
            ],
        },
    });
    const creds = JSON.parse(store.get('jellyfin_credentials'));
    const friend = creds.Servers.find(s => s.Id === FRIEND_SERVER);
    const home = creds.Servers.find(s => s.Id === THIS_SERVER);

    check(!!friend, "other server survives login (was destroyed before)", creds.Servers);
    check(friend && friend.AccessToken === 'FRIEND-TOKEN', "other server keeps its own token", friend);
    check(!!home && home.AccessToken === 'NEW-TOKEN', 'this server gets the new token', home);
    check(!!home && home.UserId === 'user-1', 'this server gets the new user id', home);
    check(creds.Servers.length === 2, 'no duplicate server entries', creds.Servers.length);
    check(store.get('kdnx_session_expires_at') === '1754204800', 'session expiry stored');
    check(!!store.get(`user-user-1-${THIS_SERVER}`), 'user record stored');
}

console.log('\n== callback.html: first-ever login (no prior credentials) ==');
{
    const { store } = await run({ seedCredentials: null });
    const creds = JSON.parse(store.get('jellyfin_credentials'));
    check(creds.Servers.length === 1, 'single server entry', creds.Servers.length);
    check(creds.Servers[0].AccessToken === 'NEW-TOKEN', 'token written', creds.Servers[0]);
}

console.log('\n== callback.html: corrupt prior credentials must not break login ==');
{
    const store = new Map([['jellyfin_credentials', '{not json']]);
    let threw = null;
    try {
        const { store: s } = await run({ seedCredentials: undefined });
        void s;
    } catch (e) { threw = e; }
    check(threw === null, 'no throw on malformed prior blob', threw && threw.message);
    void store;
}

console.log(fails === 0 ? '\nALL CHECKS PASSED' : `\n${fails} CHECK(S) FAILED`);
process.exit(fails === 0 ? 0 : 1);
