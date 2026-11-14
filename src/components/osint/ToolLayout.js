import Head from 'next/head';
import Link from 'next/link';
import s from './osint.module.css';

export const TOOL_NAV = [
    { href: '/tools/domain/', label: 'domain' },
    { href: '/tools/username/', label: 'username' },
    { href: '/tools/ip/', label: 'ip' },
    { href: '/tools/phone/', label: 'phone' },
    { href: '/tools/cli/', label: 'cli kit' }
];

export default function ToolLayout({ title, subtitle, accent = '#58a6ff', active, children }) {
    return (
        <div className={s.page} style={{ '--accent': accent }}>
            <Head>
                <title>{`${title} · OSINT Toolkit`}</title>
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <meta name="robots" content="noindex" />
            </Head>
            <div className={s.wrap}>
                <nav className={s.nav}>
                    <Link href="/tools/" className={s.brand}>
                        ~/osint
                    </Link>
                    {TOOL_NAV.map((n) => (
                        <Link key={n.href} href={n.href} className={active === n.href ? s.active : undefined}>
                            {n.label}
                        </Link>
                    ))}
                </nav>
                <h1 className={s.title}>{title}</h1>
                {subtitle && <p className={s.subtitle}>{subtitle}</p>}
                <div className={s.notice}>
                    Passive OSINT only. Use on assets you own or are authorised to assess, and respect privacy law (GDPR/CCPA) and each
                    source&apos;s terms.
                </div>
                {children}
            </div>
        </div>
    );
}

export function Terminal({ title, children }) {
    return (
        <div className={s.terminal}>
            <div className={s.termbar}>
                <span className={s.dot} style={{ background: '#ff5f57' }} />
                <span className={s.dot} style={{ background: '#febc2e' }} />
                <span className={s.dot} style={{ background: '#28c840' }} />
                <span className={s.termtitle}>zsh ~ {title}</span>
            </div>
            <div className={s.termbody}>{children}</div>
        </div>
    );
}

export function CommandForm({ cmd, placeholder, value, onChange, onSubmit, loading, inputMode, autoFocus = true }) {
    return (
        <form
            className={s.form}
            onSubmit={(e) => {
                e.preventDefault();
                if (!loading) onSubmit();
            }}
        >
            <span className={s.prompt}>$</span>
            <span className={s.cmd}>{cmd}</span>
            <input
                className={s.input}
                value={value}
                onChange={(e) => onChange(e.target.value)}
                placeholder={placeholder}
                spellCheck={false}
                autoCapitalize="off"
                autoComplete="off"
                inputMode={inputMode}
                autoFocus={autoFocus}
                aria-label={placeholder}
            />
            <button className={s.btn} disabled={loading || !value.trim()}>
                {loading ? 'running…' : 'run'}
            </button>
        </form>
    );
}

/** Fetch JSON from an /api/osint route with error handling. */
export async function callApi(path) {
    const res = await fetch(path);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `Request failed (${res.status})`);
    return body;
}

export function downloadJson(name, data) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
}

export function downloadCsv(name, rows) {
    if (!rows.length) return;
    const cols = Object.keys(rows[0]);
    const esc = (v) => `"${String(Array.isArray(v) ? v.join(' ') : v ?? '').replace(/"/g, '""')}"`;
    const csv = [cols.join(','), ...rows.map((r) => cols.map((c) => esc(r[c])).join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
}
