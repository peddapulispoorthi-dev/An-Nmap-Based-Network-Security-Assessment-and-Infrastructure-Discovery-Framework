# CN course demo plan

## Lab preparation

1. Set up a VirtualBox/VMware host-only network with Kali as the scanner and
   Metasploitable 2 plus an Ubuntu/Windows VM as targets.
2. Keep the vulnerable VM disconnected from bridged/public networks.
3. Record the authorized target IP and start Wireshark on the host-only
   interface. Ensure the scope and permission are approved in writing.

## Presentation

1. **Explain authorization.** Show that the CLI refuses to scan without
   `--i-have-permission`. Identify the lab target and the timestamped audit log.
2. **Run the assessment.** On Kali, execute against the approved lab address:

   ```bash
   sudo python3 nmap_framework.py <METASPLOITABLE_LAB_IP> --i-have-permission
   ```

   For the optional NSE phase, use `--vuln` only when its checks are approved.
   Use `--full` only if the lab scope and allotted time allow a full TCP port
   scan. Review progress, discovered hosts, services, prioritized findings, and
   the risk score.
3. **Compare packet patterns.** In the isolated lab only, capture these direct
   Nmap examples:

   ```bash
   sudo nmap -sS -p 22,80 <METASPLOITABLE_LAB_IP>
   nmap -sT -p 22,80 <METASPLOITABLE_LAB_IP>
   sudo nmap -sU --top-ports 10 <METASPLOITABLE_LAB_IP>
   ```

   Filter Wireshark for the lab target and TCP/UDP. Compare SYN probing,
   TCP-connect handshakes, and UDP probes. This project does not run a UDP scan;
   the UDP example is separate and should only be run within the approved lab.
4. **Inspect reports.** Open `scans/<timestamp>/report.html` in a browser and
   inspect `report.json`. Discuss the snapshot note, service inventory,
   severity, remediation, and any available OS/traceroute data.
5. **Demonstrate defensive remediation.** Choose a finding (for example, an
   unnecessary Telnet service), have the lab owner approve the change, disable
   or firewall it, then rerun the same assessment. Compare the reports
   manually; automated diffing is outside the MVP.
6. **Close with limitations.** Explain how firewalls/IDS, UDP behavior, banner
   uncertainty, and permissions affect observations. A finding is not proof of
   exploitability, and the framework does not execute exploits.

## Cleanup

Stop the capture, shut down the lab VMs, and handle generated reports according
to course data-handling requirements. Keep the vulnerable VM off public and
bridged networks.
