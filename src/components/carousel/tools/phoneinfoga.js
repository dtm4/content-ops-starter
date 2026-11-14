import { parsePhoneNumberFromString } from 'libphonenumber-js/max';
import { tokenize, parseArgs } from '../runtime';

const TYPE = { MOBILE: 'mobile', FIXED_LINE: 'fixed line', FIXED_LINE_OR_MOBILE: 'fixed line or mobile', TOLL_FREE: 'toll free', PREMIUM_RATE: 'premium rate', SHARED_COST: 'shared cost', VOIP: 'VoIP', PERSONAL_NUMBER: 'personal number', PAGER: 'pager', UAN: 'UAN', VOICEMAIL: 'voicemail' };
const SCANNERS = ['local', 'googlesearch'];
const g = (q) => `https://www.google.com/search?q=${encodeURIComponent(q)}`;

function dorks(p) {
    const digits = p.nationalNumber;
    const v = [...new Set([p.number, p.formatInternational(), p.formatNational(), digits, `${p.countryCallingCode}${digits}`])];
    const any = v.map((x) => `"${x}"`).join(' OR ');
    const sites = (list) => list.map((d) => `site:${d}`).join(' OR ');
    return {
        'Social media': [['facebook.com'], ['instagram.com'], ['linkedin.com'], ['twitter.com', 'x.com'], ['vk.com'], ['tiktok.com']].map((s) => `${sites(s)} (${any})`),
        'Disposable providers': [`${sites(['receive-sms-online.info', 'receive-sms.com', 'sms-receive.net', 'freephonenum.com', 'receivesmsonline.net', 'smsreceivefree.com'])} "${digits}"`],
        Reputation: [`${sites(['whosenumber.info', 'tellows.com', 'whocalled.us', 'shouldianswer.com', '800notes.com'])} "${digits}"`, `(${any}) (scam OR spam OR fraud)`],
        Individuals: [`${sites(['numinfo.net', 'sync.me', 'whocallsyou.de', 'pastebin.com', 'whitepages.com', 'truepeoplesearch.com', 'spokeo.com'])} (${any})`],
        General: [any, `(${any}) (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:sxw OR ext:psw OR ext:ppt OR ext:pptx OR ext:pps OR ext:csv OR ext:txt OR ext:xls)`]
    };
}

export default {
    id: 'phoneinfoga',
    n: '06',
    name: 'phoneinfoga',
    color: '#f0883e',
    subtitle: 'Phone number OSINT (footprints)',
    example: 'phoneinfoga scan -n +12025550143',
    comment: 'phone number osint (footprints)',
    usage: [
        ['-n', 'number to scan (E164)'],
        ['-D', 'skip a scanner'],
        ['-', 'plugin: add a scanner (CLI kit)'],
        ['serve', 'launch web UI']
    ],
    overview:
        'phoneinfoga profiles a phone number from its digits. Feed it an E164 number and it parses country and format, then builds ready-to-run search-engine footprints to surface it across social and people-finder sites.',

    async exec(line, io) {
        const argv = tokenize(line);
        if (!/^phoneinfoga$/i.test(argv[0] || '')) return io.print(`zsh: command not found: ${argv[0]}. Try: ${this.example}`, 'bad');
        const [cmd, ...rest] = argv.slice(1);
        if (cmd === 'serve') {
            io.print('This carousel slide is the web UI. Locally: ./osint phoneinfoga serve -p 8080 (CLI kit)', 'accent');
            return;
        }
        if (cmd === 'version') return io.print('phoneinfoga web edition (scanners: local, googlesearch)');
        if (cmd !== 'scan') {
            io.print('Usage: phoneinfoga scan -n NUMBER [-D scanner]   |   phoneinfoga serve');
            return;
        }
        const { opts, unknown } = parseArgs(rest, { n: 'value', number: 'value', D: 'multi', disable: 'multi' });
        unknown.forEach((u) => io.print(`[!] ignoring unsupported option ${u}`, 'warn'));
        const raw = String(opts.n || opts.number || '').replace(/[^\d+]/g, '');
        if (!raw) return io.print('Error: -n NUMBER is required, e.g. phoneinfoga scan -n +12025550143', 'bad');
        const disabled = [...(opts.D || []), ...(opts.disable || [])].flatMap((x) => x.split(','));
        const p = parsePhoneNumberFromString(raw.startsWith('+') ? raw : `+${raw}`);
        if (!p) return io.print('Error: could not parse number. Use E164: +[country code][number]', 'bad');

        io.print(`Running scan for phone number ${p.number}...`, 'accent');
        io.print('');
        const results = { number: p.number };
        if (!disabled.includes('local')) {
            io.print('Results for local', 'accent');
            const local = {
                'Raw local': p.nationalNumber,
                Local: p.formatNational(),
                E164: p.number,
                International: `${p.countryCallingCode}${p.nationalNumber}`,
                Country: `${p.country || '?'} (+${p.countryCallingCode})`,
                'Line type': TYPE[p.getType()] || 'unknown',
                Valid: p.isValid() ? 'yes' : 'no (format possible, range unassigned)'
            };
            Object.entries(local).forEach(([k, v]) => io.print(`${k}: ${v}`, k === 'Valid' && !p.isValid() ? 'warn' : 'plain'));
            results.local = local;
            io.print('');
        }
        if (!disabled.includes('googlesearch')) {
            io.print('Results for googlesearch', 'accent');
            const d = dorks(p);
            results.googlesearch = d;
            for (const [group, qs] of Object.entries(d)) {
                io.print(`${group}:`);
                qs.forEach((q) => io.print(`    ↗ ${q}`, 'link', g(q)));
            }
            io.print('');
        }
        disabled.filter((s) => SCANNERS.includes(s)).forEach((s) => io.print(`Scanner ${s} skipped (-D)`, 'muted'));
        disabled.filter((s) => !SCANNERS.includes(s)).forEach((s) => io.print(`Scanner ${s} not present (numverify/ovh need API keys: CLI kit)`, 'muted'));
        io.print(`${SCANNERS.filter((s) => !disabled.includes(s)).length} scanner(s) succeeded`, 'ok');
        io.print('Runs entirely in your browser. The number is not sent anywhere until you open a footprint.', 'muted');
        io.exports({ [`phoneinfoga-${p.number}.json`]: () => JSON.stringify(results, null, 2) });
    }
};
