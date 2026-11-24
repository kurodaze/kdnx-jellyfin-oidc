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
        .replaceAll('"___jsonPathBase___"', '""')
        .replaceAll('"___jsonAuthUrl___"', '"/sso/OID/Auth/KDNX"')
        .replaceAll('"___jsonData___"', '"one-time-token"');
}

// seedCredentials may be an object, or a raw string to plant a malformed blob.
async function run({
    seedCredentials = null,
    seedDeviceId = 'device-abc',
    nativeShell = null,
    userAgent = 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0',
    fetchOk = true,
} = {}) {
    const store = new Map();
    if (seedCredentials) {
        store.set('jellyfin_credentials', typeof seedCredentials === 'string'
            ? seedCredentials
            : JSON.stringify(seedCredentials));
    }
    if (seedDeviceId) {
        store.set('_deviceId2', seedDeviceId);
    }

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

    let postedBody = null;
    const message = { textContent: '' };
    const sandbox = {
        localStorage,
        navigator: { userAgent, maxTouchPoints: 0 },
        document: {
            getElementById: () => iframe,
            querySelector: () => message,
            addEventListener: () => {},
        },
        window: nativeShell ? { NativeShell: nativeShell } : {},
        setTimeout,
        console,
        JSON,
        fetch: async (_url, opts) => {
            postedBody = JSON.parse(opts.body);
            return {
                ok: fetchOk,
                json: async () => ({
                    User: { Id: 'user-1', ServerId: THIS_SERVER, Name: 'kuro' },
                    AccessToken: 'NEW-TOKEN',
                }),
            };
        },
    };
    sandbox.window.location = { replace: () => {} };

    const ctx = vm.createContext(sandbox);
    vm.runInContext(extractScript() + '\n;globalThis.__main = main;', ctx);
    await ctx.__main();

    return { store, message, postedBody };
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
    check(!!store.get(`user-user-1-${THIS_SERVER}`), 'user record stored');
}

console.log('\n== callback.html: failed login restores prior credentials ==');
{
    const prior = {
        Servers: [
            { Id: FRIEND_SERVER, Name: "friend's server", AccessToken: 'FRIEND-TOKEN', UserId: 'friend-user' },
        ],
    };
    const { store, message } = await run({ seedCredentials: prior, fetchOk: false });
    const creds = JSON.parse(store.get('jellyfin_credentials'));
    check(creds.Servers.length === 1 && creds.Servers[0].Id === FRIEND_SERVER,
        'prior credentials restored on auth failure', creds);
    check(message.textContent.includes('Authentication failed'), 'displays error message', message.textContent);
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
    let threw = null;
    let store = null;
    try {
        ({ store } = await run({ seedCredentials: '{not json' }));
    } catch (e) { threw = e; }
    check(threw === null, 'no throw on malformed prior blob', threw && threw.message);
    const creds = threw ? null : JSON.parse(store.get('jellyfin_credentials'));
    check(!!creds && creds.Servers[0].AccessToken === 'NEW-TOKEN', 'login still completes', creds);
}

console.log('\n== callback.html: NativeShell device seeding and browser UA detection ==');
{
    const { store, postedBody } = await run({
        seedDeviceId: null,
        nativeShell: { AppHost: { deviceId: () => 'android-dev-42', appName: () => 'Jellyfin Android' } },
    });
    check(store.get('_deviceId2') === 'android-dev-42', 'NativeShell deviceId seeded into _deviceId2', store.get('_deviceId2'));
    check(postedBody.deviceId === 'android-dev-42' && postedBody.appName === 'Jellyfin Android',
        'NativeShell metadata posted to /OID/Auth', postedBody);

    const edge = await run({
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
    });
    check(edge.postedBody.deviceName === 'Edge', 'detects Chromium Edge ahead of Chrome', edge.postedBody.deviceName);

    const opera = await run({
        userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36 OPR/114.0.0.0',
    });
    check(opera.postedBody.deviceName === 'Opera', 'detects Chromium Opera ahead of Chrome', opera.postedBody.deviceName);
}

console.log(fails === 0 ? '\nALL CHECKS PASSED' : `\n${fails} CHECK(S) FAILED`);
process.exit(fails === 0 ? 0 : 1);
