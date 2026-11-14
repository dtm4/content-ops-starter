import Link from 'next/link';
import ToolLayout from '../../components/osint/ToolLayout';
import s from '../../components/osint/osint.module.css';

const TOOLS = [
    {
        n: '01',
        name: 'Domain Recon',
        c: '#58a6ff',
        href: '/tools/domain/',
        tag: 'Subdomains, hosts, DNS and emails',
        body: 'Pulls subdomains from certificate transparency, host/IP pairs from HackerTarget, and the full DNS record set, then draws them as a link graph.',
        mode: 'Web · theHarvester + recon-ng (hackertarget) + Maltego-style graph'
    },
    {
        n: '02',
        name: 'Username Search',
        c: '#e3b341',
        href: '/tools/username/',
        tag: 'One handle checked across 34 sites',
        body: 'Checks GitHub, Reddit, social, media and gaming sites in parallel and lists candidate profiles to verify by hand.',
        mode: 'Web · Sherlock-style (full 400+ sites in CLI kit)'
    },
    {
        n: '03',
        name: 'IP Exposure',
        c: '#3fb950',
        href: '/tools/ip/',
        tag: 'Open ports, CPEs and CVEs for an IP',
        body: "Queries Shodan's existing scan data (no packets sent to the target): ports, hostnames, software and known vulns.",
        mode: 'Web · Shodan InternetDB (+ full host API with key)'
    },
    {
        n: '04',
        name: 'Phone Profiler',
        c: '#f0883e',
        href: '/tools/phone/',
        tag: 'Number parsing + search footprints',
        body: 'Parses an E.164 number (country, type, formats) and builds ready-to-run search-engine footprints.',
        mode: 'Web · PhoneInfoga-style, runs in your browser'
    },
    {
        n: '05',
        name: 'CLI Kit',
        c: '#bc8cff',
        href: '/tools/cli/',
        tag: 'The real tools, one installer',
        body: 'Installs and runs theHarvester, SpiderFoot, Sherlock, Shodan CLI, PhoneInfoga and recon-ng from one ./osint launcher. Maltego setup notes included.',
        mode: 'Local · osint-kit/ in this repo'
    }
];

export default function ToolsIndex() {
    return (
        <ToolLayout title="OSINT Toolkit" subtitle="Passive recon in the browser, the full toolchain on the CLI.">
            <div className={s.grid}>
                {TOOLS.map((t) => (
                    <Link key={t.n} href={t.href} className={s.card} style={{ '--c': t.c }}>
                        <span className={s.cardNum}>{t.n}</span>
                        <div className={s.cardName}>{t.name}</div>
                        <div className={s.cardTag}>{t.tag}</div>
                        <div>{t.body}</div>
                        <div className={s.cardMode}>{t.mode}</div>
                    </Link>
                ))}
            </div>
        </ToolLayout>
    );
}
