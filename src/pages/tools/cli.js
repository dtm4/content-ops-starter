import ToolLayout, { Terminal } from '../../components/osint/ToolLayout';
import s from '../../components/osint/osint.module.css';

const TOOLS = [
    ['01', 'theHarvester', '#58a6ff', './osint theharvester -d example.com -b crtsh,hackertarget -f out', 'Emails, subdomains, hosts and IPs from 50+ sources'],
    ['02', 'SpiderFoot', '#bc8cff', './osint spiderfoot -s example.com -u passive -o csv', '200+ modules with a correlation engine; web UI on -l 127.0.0.1:5001'],
    ['03', 'Maltego', '#ff7eb6', './osint maltego', 'Desktop GUI (free Community tier); setup notes and CSV import'],
    ['04', 'Sherlock', '#e3b341', './osint sherlock johndoe --print-found', 'One username checked across 400+ sites'],
    ['05', 'Shodan', '#3fb950', './osint shodan host 198.51.100.23', 'Needs a key: ./osint shodan init <KEY>'],
    ['06', 'PhoneInfoga', '#f0883e', './osint phoneinfoga scan -n +12025550143', 'Phone number footprints; web UI via serve -p 8080'],
    ['07', 'recon-ng', '#58a6ff', './osint reconng', 'Modular framework: marketplace install, then modules load, options set, run']
];

export default function CliPage() {
    return (
        <ToolLayout active="/tools/cli/" title="CLI Kit" subtitle="The real tools from one installer, in osint-kit/ in this repo" accent="#bc8cff">
            <Terminal title="osint-kit">
                <pre className={s.code} style={{ border: 'none', padding: 0, margin: 0, background: 'transparent' }}>
                    {`$ git clone <this repo> && cd content-ops-starter/osint-kit
$ ./osint install          # all tools -> ~/.osint-kit (isolated venvs)
$ ./osint doctor           # check status`}
                </pre>
            </Terminal>
            <div className={s.sectionLabel}>Usage</div>
            <div className={s.tableWrap}>
                <table className={s.table}>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>tool</th>
                            <th>command</th>
                        </tr>
                    </thead>
                    <tbody>
                        {TOOLS.map(([n, name, c, cmd, desc]) => (
                            <tr key={n}>
                                <td className={s.muted}>{n}</td>
                                <td style={{ color: c, fontWeight: 700, whiteSpace: 'nowrap' }}>{name}</td>
                                <td>
                                    <code>{cmd}</code>
                                    <div className={s.muted} style={{ fontSize: 12 }}>
                                        {desc}
                                    </div>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
            <p className={s.hint}>Requires Linux or macOS (WSL2 on Windows), Python 3.10+, git and curl. See osint-kit/README.md for the full workflow.</p>
        </ToolLayout>
    );
}
