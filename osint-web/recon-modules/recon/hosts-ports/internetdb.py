from recon.core.module import BaseModule


class Module(BaseModule):

    meta = {
        'name': 'Shodan InternetDB Port and CVE Lookup',
        'author': 'osint-web',
        'version': '1.0',
        'description': 'Looks up each host IP in Shodan InternetDB (free, no API key) and adds open '
                       'ports and known CVEs to the ports and vulnerabilities tables. Passive: uses '
                       "Shodan's existing scan data.",
        'query': 'SELECT DISTINCT ip_address FROM hosts WHERE ip_address IS NOT NULL',
    }

    def module_run(self, ips):
        for ip in ips:
            self.heading(ip, level=0)
            resp = self.request('GET', f'https://internetdb.shodan.io/{ip}')
            if resp.status_code == 404:
                self.output('No data.')
                continue
            if resp.status_code != 200:
                self.error(f'InternetDB returned HTTP {resp.status_code}')
                continue
            data = resp.json()
            names = data.get('hostnames') or []
            host = names[0] if names else None
            for port in data.get('ports') or []:
                self.insert_ports(ip_address=ip, host=host, port=port, protocol='tcp')
            for cve in data.get('vulns') or []:
                self.insert_vulnerabilities(host=host or ip, reference=cve, category='CVE',
                                            notes='Inferred from service banner by Shodan InternetDB')
            for name in names:
                self.insert_hosts(host=name, ip_address=ip)
