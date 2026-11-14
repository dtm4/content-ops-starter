import { useMemo, useState } from 'react';
import { parsePhoneNumberFromString } from 'libphonenumber-js/max';
import ToolLayout, { Terminal, CommandForm } from '../../components/osint/ToolLayout';
import s from '../../components/osint/osint.module.css';

// PhoneInfoga-style local scan: parsing happens entirely in the browser,
// footprints are search URLs the analyst opens manually.

const TYPE_LABEL = {
    MOBILE: 'Mobile',
    FIXED_LINE: 'Fixed line',
    FIXED_LINE_OR_MOBILE: 'Fixed line or mobile',
    TOLL_FREE: 'Toll free',
    PREMIUM_RATE: 'Premium rate',
    SHARED_COST: 'Shared cost',
    VOIP: 'VoIP',
    PERSONAL_NUMBER: 'Personal number',
    PAGER: 'Pager',
    UAN: 'UAN',
    VOICEMAIL: 'Voicemail'
};

const g = (q) => `https://www.google.com/search?q=${encodeURIComponent(q)}`;
const ddg = (q) => `https://duckduckgo.com/?q=${encodeURIComponent(q)}`;

function buildFootprints(p) {
    const e164 = p.number; // +12025550143
    const intl = p.formatInternational(); // +1 202 555 0143
    const natl = p.formatNational(); // (202) 555-0143
    const digits = p.nationalNumber; // 2025550143
    const variants = [...new Set([e164, intl, natl, digits, `${p.countryCallingCode}${digits}`])];
    const any = variants.map((v) => `"${v}"`).join(' OR ');

    const groups = {
        'General': [
            { label: 'All formats', q: any },
            { label: 'Documents (pdf/doc/xls)', q: `(${any}) (ext:pdf OR ext:doc OR ext:docx OR ext:xls OR ext:xlsx OR ext:txt)` }
        ],
        'Social networks': [
            ['facebook.com'],
            ['instagram.com'],
            ['linkedin.com'],
            ['twitter.com', 'x.com'],
            ['vk.com'],
            ['tiktok.com']
        ].map((sites) => ({ label: sites[0], q: `${sites.map((d) => `site:${d}`).join(' OR ')} (${any})` })),
        'Reputation / spam reports': ['tellows.com', 'whocalledme.com', 'shouldianswer.com', 'callercenter.com', '800notes.com', 'scamnumbers.info'].map(
            (d) => ({ label: d, q: `site:${d} "${digits}"` })
        ),
        'People finders / directories': ['whitepages.com', 'truepeoplesearch.com', 'fastpeoplesearch.com', 'spokeo.com', 'numlookup.com', 'sync.me'].map(
            (d) => ({ label: d, q: `site:${d} (${any})` })
        ),
        'Messaging (manual check)': [
            { label: 'WhatsApp click-to-chat', url: `https://wa.me/${e164.replace('+', '')}` },
            { label: 'Telegram', url: `https://t.me/${e164}` }
        ]
    };
    return { variants, groups };
}

export default function PhonePage() {
    const [q, setQ] = useState('');
    const [submitted, setSubmitted] = useState('');

    const result = useMemo(() => {
        if (!submitted) return null;
        const p = parsePhoneNumberFromString(submitted.startsWith('+') ? submitted : `+${submitted}`);
        if (!p) return { error: 'Could not parse. Use E.164 format, e.g. +12025550143' };
        return { p, ...buildFootprints(p) };
    }, [submitted]);

    return (
        <ToolLayout active="/tools/phone/" title="Phone Profiler" subtitle="Phone number OSINT (footprints)" accent="#f0883e">
            <Terminal title="phoneinfoga">
                <CommandForm
                    cmd="phoneinfoga scan -n"
                    placeholder="+12025550143"
                    value={q}
                    onChange={setQ}
                    onSubmit={() => setSubmitted(q.replace(/[^\d+]/g, ''))}
                    loading={false}
                    inputMode="tel"
                />
                <div className={s.hint}>Runs entirely in your browser. The number never leaves this page until you click a footprint.</div>
                {result?.error && <div className={s.error}>{result.error}</div>}
            </Terminal>

            {result?.p && (
                <>
                    <div className={s.sectionLabel}>Local scan</div>
                    <dl className={s.kv}>
                        <dt>valid</dt>
                        <dd className={result.p.isValid() ? s.found : s.error_}>{result.p.isValid() ? 'yes' : 'no (format is possible but number range is not assigned)'}</dd>
                        <dt>e164</dt>
                        <dd>{result.p.number}</dd>
                        <dt>international</dt>
                        <dd>{result.p.formatInternational()}</dd>
                        <dt>national</dt>
                        <dd>{result.p.formatNational()}</dd>
                        <dt>country</dt>
                        <dd>
                            {result.p.country || '-'} (+{result.p.countryCallingCode})
                        </dd>
                        <dt>line type</dt>
                        <dd>{TYPE_LABEL[result.p.getType()] || 'Unknown'}</dd>
                        <dt>uri</dt>
                        <dd>{result.p.getURI()}</dd>
                    </dl>
                    <p className={s.hint}>
                        Line type comes from the original numbering plan. Ported numbers keep their original type, and carrier data isn&apos;t
                        available offline.
                    </p>

                    {Object.entries(result.groups).map(([group, items]) => (
                        <div key={group}>
                            <div className={s.sectionLabel}>{group}</div>
                            <div className={s.tableWrap}>
                                <table className={s.table}>
                                    <tbody>
                                        {items.map((it) => (
                                            <tr key={it.label}>
                                                <td style={{ width: '30%' }}>{it.label}</td>
                                                <td>
                                                    {it.url ? (
                                                        <a href={it.url} target="_blank" rel="noopener noreferrer nofollow">
                                                            {it.url}
                                                        </a>
                                                    ) : (
                                                        <>
                                                            <a href={g(it.q)} target="_blank" rel="noopener noreferrer nofollow">
                                                                google
                                                            </a>{' '}
                                                            ·{' '}
                                                            <a href={ddg(it.q)} target="_blank" rel="noopener noreferrer nofollow">
                                                                ddg
                                                            </a>
                                                            <div className={s.muted} style={{ fontSize: 12, marginTop: 4 }}>
                                                                {it.q}
                                                            </div>
                                                        </>
                                                    )}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    ))}
                </>
            )}
        </ToolLayout>
    );
}
