#!/usr/bin/env bash
# nscan - scan a host list with nmap, named and timestamped output.
#
# Usage:   nscan.sh -i targets.txt -o vessel01 [-a "<nmap args>"] [-d outdir] [-p] [-n]
# Example: nscan.sh -i targets.txt -o vessel01 -a "-sT -T2 --scan-delay 100ms" -p
# Needs:   nmap, sudo
#
#   -i  target file, one entry per line. Accepts IPs, ranges and CIDR.
#   -o  job name. Goes into every filename, so make it the vessel or the site.
#   -a  nmap arguments, replacing the default "-sS -Pn --open".
#   -d  output directory, default ./scans
#   -p  one scan and one output set per host, instead of one for the whole list.
#   -n  dry run. Print the nmap commands that would run, then exit.
set -euo pipefail

# -sS needs raw sockets. Without root, nmap quietly falls back to a connect
# scan, which behaves differently on fragile stacks and changes what you find.
# Re-exec once under sudo rather than discovering this halfway through a job.
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  command -v sudo >/dev/null || { echo "nscan: run as root, sudo not available" >&2; exit 2; }
  exec sudo -E -- "$0" "$@"
fi

NMAP_ARGS="-sS -Pn --open"
OUTDIR="scans"
PER_HOST=0
DRYRUN=0
TARGETS=""
NAME=""

usage() { sed -n '2,13p' "$0" >&2; exit 1; }

while getopts ":i:o:a:d:pnh" opt; do
  case "$opt" in
    i) TARGETS=$OPTARG ;;
    o) NAME=$OPTARG ;;
    a) NMAP_ARGS=$OPTARG ;;
    d) OUTDIR=$OPTARG ;;
    p) PER_HOST=1 ;;
    n) DRYRUN=1 ;;
    *) usage ;;
  esac
done

[[ -n $TARGETS && -n $NAME ]] || usage
[[ -r $TARGETS ]] || { echo "nscan: cannot read $TARGETS" >&2; exit 2; }
command -v nmap >/dev/null || { echo "nscan: nmap not installed" >&2; exit 2; }

# The job name ends up in filenames, so fold anything that is not alphanumeric,
# dot, underscore or dash into an underscore.
SAFE=$(printf '%s' "$NAME" | tr -c '[:alnum:]._-' '_')
STAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p "$OUTDIR"

# Strip trailing comments and blank lines, and keep the result as a real file
# next to the scan output. That way the printed command is reproducible later
# and you have a record of exactly which targets this run covered.
CLEAN="$OUTDIR/${STAMP}_${SAFE}.targets"
sed 's/#.*//' "$TARGETS" | awk 'NF {print $1}' > "$CLEAN"
[[ -s $CLEAN ]] || { echo "nscan: no usable targets in $TARGETS" >&2; exit 2; }

# Split the nmap argument string once, into an array, so no quoting surprises.
read -r -a NMAP_ARR <<< "$NMAP_ARGS"

# Every scan prints the plain nmap command before running it. Paste it into a
# report, rerun it by hand, or just check what the wrapper is doing for you.
run() {
  echo "+ nmap $*"
  (( DRYRUN )) && return 0
  nmap "$@" </dev/null    # </dev/null stops nmap eating the loop's stdin
}

if (( PER_HOST )); then
  while IFS= read -r host; do
    out="$OUTDIR/${STAMP}_${SAFE}_${host//[^[:alnum:]]/-}"
    if [[ -f $out.gnmap ]] && grep -q "Nmap done" "$out.gnmap"; then
      echo "[skip] $host already complete"; continue
    fi
    echo "[scan] $host"
    run "${NMAP_ARR[@]}" "$host" -oA "$out"
  done < "$CLEAN"
else
  out="$OUTDIR/${STAMP}_${SAFE}"
  echo "[scan] $(wc -l < "$CLEAN") hosts -> $out.{nmap,gnmap,xml}"
  run "${NMAP_ARR[@]}" -iL "$CLEAN" -oA "$out"
fi

echo "[done] $OUTDIR"