# College presentation demo script

## Before the presentation

- Use an isolated VirtualBox host-only network containing the Kali assessment
  VM and Metasploitable 2 target. Confirm the target address and written scope.
- Keep both VMs off bridged/public networks. Install Nmap and this framework.
- Install Wireshark in the Kali VM or on a capture interface attached to the
  host-only segment. Start a capture on that interface.
- Never use a public/production target for this demo. Do not run exploit modules.

## Demonstration

1. **Explain authorization and scope.** Show the target VM's host-only address
   and the explicit authorization flag/checkbox. Point out `logs/audit.log`.
2. **Run discovery and inventory.** On Kali, run:

   ```bash
   python -m nmapfw scan <METASPLOITABLE_LAB_IP> --profile standard --i-have-permission
   ```

   Review phase progress, discovered hosts, open services, findings, and risk.
   In the dashboard, submit the same scoped target and inspect the progress and
   results pages.
3. **Compare Wireshark scan traffic.** In the isolated lab only, capture:

   ```bash
   sudo nmap -sS -p 22,80 <METASPLOITABLE_LAB_IP>
   nmap -sT -p 22,80 <METASPLOITABLE_LAB_IP>
   sudo nmap -sU --top-ports 10 <METASPLOITABLE_LAB_IP>
   ```

   Filter Wireshark for the target IP and TCP/UDP. Contrast SYN probing,
   TCP-connect handshakes, and UDP probes. Explain that capture details depend
   on the network, privileges, and target responses. These comparison commands
   are only for the isolated, authorized lab.
4. **Open a report.** Use the report downloads in the web results page, or run:

   ```bash
   python -m nmapfw report <SCAN_ID> --format html --out ./demo-report.html
   ```

   Open the HTML file and review the point-in-time snapshot note, risk score,
   service table, remediation text, and traceroute path if available.
5. **Apply a defensive fix.** Choose one low-risk lab finding, such as disabling
   an unused exposed service or restricting its host firewall rule. Make only a
   configuration change you understand; do not exploit or modify the VM beyond
   the agreed lab exercise.
6. **Rescan and compare.** Repeat the same profile and target after the fix,
   then compare the saved scan IDs:

   ```bash
   python -m nmapfw scan <METASPLOITABLE_LAB_IP> --profile standard --i-have-permission
   python -m nmapfw diff <BEFORE_SCAN_ID> <AFTER_SCAN_ID>
   ```

   Show the newly closed port or other observed change. Explain that a diff
   reflects Nmap's observations and that service changes may require manual
   confirmation.
7. **Close with limitations.** Emphasize written authorization, isolated scope,
   heuristic scoring, banner/version uncertainty, and the fact that this tool
   does not verify fixes by exploitation.

## Cleanup

Stop the capture, shut down the lab VMs, retain or remove the generated reports
according to the course's data-handling rules, and keep the vulnerable target
off public/bridged networks.
