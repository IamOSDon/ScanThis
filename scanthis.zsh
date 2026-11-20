scanthis() {
  [ -n "$1" ] || { echo "Usage: scanthis <IP>"; return 1; }

  local target="$1" name="${1//[^A-Za-z0-9._-]/_}"
  local outdir="recon/nmap" ports udp_ports scripts vuln_ports report
  mkdir -p "$outdir"

  _scanthis_run() {
    local arg
    printf '[CMD]'
    for arg; do printf ' %q' "$arg"; done
    printf '\n'
    command "$@"
  }

  echo "[*] Full TCP scan"
  _scanthis_run nmap -Pn -n -sT -p- --min-rate 1000 "$target" \
    -oA "$outdir/$name-01-all-tcp"

  ports=$(grep -oE '[0-9]+/open' "$outdir/$name-01-all-tcp.gnmap" 2>/dev/null |
    cut -d/ -f1 | sort -n -u | paste -sd,)

  echo "[+] TCP ports: ${ports:-none}"

  if [ -n "$ports" ]; then
    echo "[*] Service scan"
    _scanthis_run nmap -Pn -n -sT -p "$ports" -sC -sV --version-intensity 7 "$target" \
      -oA "$outdir/$name-02-services"
  fi

  scripts=""
  echo "$ports" | grep -qE '(^|,)445(,|$)' &&
    scripts="${scripts:+$scripts,}smb-vuln*"
  echo "$ports" | grep -qE '(^|,)21(,|$)' &&
    scripts="${scripts:+$scripts,}ftp-anon,ftp-vsftpd-backdoor,ftp-proftpd-backdoor"
  echo "$ports" | grep -qE '(^|,)(80|443|8000|8080|8081|8443|8888)(,|$)' &&
    scripts="${scripts:+$scripts,}http-shellshock"
  echo "$ports" | grep -qE '(^|,)(25|587)(,|$)' &&
    scripts="${scripts:+$scripts,}smtp-vuln*"

  if [ -n "$scripts" ]; then
    vuln_ports=$(echo "$ports" | tr ',' '\n' |
      grep -E '^(21|25|80|139|443|445|587|8000|8080|8081|8443|8888)$' |
      paste -sd,)

    if [ -n "$vuln_ports" ]; then
      echo "[*] Selected NSE scripts"
      _scanthis_run nmap -Pn -n -sT -p "$vuln_ports" --script "$scripts" "$target" \
        -oA "$outdir/$name-03-nse"
    fi
  fi

  echo "[*] UDP top 100"
  _scanthis_run nmap -Pn -n -sU --top-ports 100 "$target" \
    -oA "$outdir/$name-04-udp"

  udp_ports=$(grep -oE '[0-9]+/open' "$outdir/$name-04-udp.gnmap" 2>/dev/null |
    cut -d/ -f1 | sort -n -u | paste -sd,)

  echo "[+] UDP ports: ${udp_ports:-none}"

  if echo "$udp_ports" | grep -qE '(^|,)161(,|$)'; then
    echo "[*] SNMP enumeration"
    _scanthis_run nmap -Pn -n -sU -p 161 \
      --script snmp-info,snmp-interfaces,snmp-processes,snmp-sysdescr "$target" \
      -oA "$outdir/$name-05-snmp"
  fi

  report="$outdir/$name-report.md"
  {
    echo "# scanthis report: $target"
    echo
    echo "## Open ports"
    echo
    echo "- TCP: ${ports:-none}"
    echo "- UDP: ${udp_ports:-none}"
    echo
    echo "## Scan output"
    for f in "$outdir"/"$name"-*.nmap(N); do
      echo
      echo "### $(basename "$f")"
      echo
      echo '```text'
      cat "$f"
      echo '```'
    done
    echo
    echo "## Interesting strings"
    echo
    echo '```text'
    grep -Ein 'password|passwd|secret|token|api.?key|private.?key|flag|anonymous|vulnerable|exploit|CVE-[0-9]+' \
      "$outdir"/"$name"-*.nmap(N) 2>/dev/null || true
    echo '```'
  } > "$report"

  echo "[+] Report: $report"
}
