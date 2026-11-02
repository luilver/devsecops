#!/usr/bin/env bash
#
# check_cve_2026_98432.sh — detect and mitigate CVE-2026-98432
#   "ipv4: free inet_opt and ireq_opt after an RCU grace period"
#   Remote unauthenticated use-after-free in the IPv4 TCP handshake.
#
# Reads the running kernel, compares it against the distribution's fixed
# package version (or the upstream stable version), reports exposure, and can
# install an interim nftables/iptables rule that drops the trigger.
#
# Usage:
#   ./check_cve_2026_98432.sh check            # read-only, exit 0/2/3
#   ./check_cve_2026_98432.sh status           # verbose report
#   sudo ./check_cve_2026_98432.sh apply       # install mitigation if unpatched
#   sudo ./check_cve_2026_98432.sh remove      # remove mitigation
#
# Options:
#   --method auto|nft|iptables   mitigation backend (default: auto)
#   --disable-mptcp              also set net.mptcp.enabled=0 (opt-in)
#   --dry-run                    print actions without changing anything
#   -h, --help
#
# Exit codes for "check": 0 patched, 2 vulnerable, 3 undetermined, 1 error.
#
set -euo pipefail

CVE="CVE-2026-98432"
NFT_TABLE_FAMILY="ip"
NFT_TABLE_NAME="cve_2026_98432"
IPT_COMMENT="cve-2026-98432"
SYSCTL_DROPIN="/etc/sysctl.d/90-cve-2026-98432-mptcp.conf"
STATE_DIR="/var/lib/cve-2026-98432"

ACTION="check"
METHOD="auto"
DISABLE_MPTCP=false
DRY_RUN=false

KSTATUS="unknown"
KREASON=""
KERNEL_REL=""
KERNEL_PKG=""
DISTRO_ID="unknown"
DISTRO_NAME="unknown"
IN_CONTAINER=false

info() { printf '%s\n' "$*"; }
ok()   { printf '  [ok]   %s\n' "$*"; }
warn() { printf '  [warn] %s\n' "$*" >&2; }
fail() { printf '  [fail] %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() { awk 'NR==1{next} /^set -euo/{exit} {sub(/^# ?/,""); print}' "$0"; }

version_ge() {
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | tail -n1)" = "$1" ]
}

base3() { printf '%s' "${1%%-*}" | awk -F. '{printf "%d.%d.%d", $1, $2, $3}'; }
branch() { base3 "$1" | awk -F. '{print $1"."$2}'; }

detect_distro() {
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_NAME="${PRETTY_NAME:-${NAME:-unknown}}"
  fi
  case "$(uname -r)" in
    *-pve) DISTRO_ID="proxmox"; DISTRO_NAME="Proxmox VE" ;;
  esac
  if have pveversion; then DISTRO_ID="proxmox"; fi
}

detect_container() {
  if [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then
    IN_CONTAINER=true
  elif grep -qaE 'docker|kubepods|containerd|lxc' /proc/1/cgroup 2>/dev/null; then
    IN_CONTAINER=true
  fi
}

kernel_package_version() {
  local rel="$1" v
  if have dpkg-query; then
    v=$(dpkg-query -W -f='${Version}' "linux-image-$rel" 2>/dev/null) && { printf '%s' "$v"; return 0; }
    v=$(dpkg-query -W -f='${Version}' "proxmox-kernel-$rel" 2>/dev/null) && { printf '%s' "$v"; return 0; }
  fi
  if have rpm; then
    v=$(rpm -q "kernel-$rel" --qf '%{VERSION}-%{RELEASE}' 2>/dev/null) || true
    case "$v" in ""|*"not installed"*) ;; *) printf '%s' "$v"; return 0;; esac
  fi
  return 1
}

distro_fixed_version() {
  local base="$1"
  case "$DISTRO_ID" in
    ubuntu|linuxmint|pop|zorin|elementary)
      case "$base" in
        5.15.*) printf '5.15.0-203.213' ;;
        6.8.*)  printf '6.8.0-149.149' ;;
        7.0.*)  printf '7.0.0-43.43' ;;
        7.3.*)  printf '7.3.0-10.10' ;;
        *) return 1 ;;
      esac ;;
    debian)
      case "$base" in
        6.1.*)  printf '6.1.190-1' ;;
        6.12.*) printf '6.12.113-1' ;;
        *) return 1 ;;
      esac ;;
    rhel|centos|rocky|almalinux|ol|fedora)
      case "$base" in
        4.18.*) printf '4.18.0-553.182.1' ;;
        5.14.*) printf '5.14.0-687.64.1' ;;
        6.12.*) printf '6.12.0-211.72.1' ;;
        *) return 1 ;;
      esac ;;
    *) return 1 ;;
  esac
}

upstream_fixed_version() {
  case "$1" in
    5.10) printf '5.10.272' ;;
    5.15) printf '5.15.223' ;;
    6.1)  printf '6.1.190' ;;
    6.6)  printf '6.6.159' ;;
    6.12) printf '6.12.113' ;;
    6.18) printf '6.18.56' ;;
    7.2)  printf '7.2.10' ;;
    *) return 1 ;;
  esac
}

classify() {
  KERNEL_REL="$(uname -r)"
  local base br fixed
  base="$(base3 "$KERNEL_REL")"
  br="$(branch "$KERNEL_REL")"
  KERNEL_PKG="$(kernel_package_version "$KERNEL_REL" || true)"

  if [ "$DISTRO_ID" = "proxmox" ]; then
    KSTATUS="unknown"
    KREASON="Proxmox kernel $KERNEL_REL ships its own branch; no fixed pve build published yet. Treat as vulnerable."
    return
  fi

  if fixed="$(distro_fixed_version "$base")"; then
    if [ -n "$KERNEL_PKG" ]; then
      if version_ge "${KERNEL_PKG%%+*}" "$fixed"; then
        KSTATUS="patched"
        KREASON="package $KERNEL_PKG >= fixed $fixed"
      else
        KSTATUS="vulnerable"
        KREASON="package $KERNEL_PKG < fixed $fixed"
      fi
    else
      KSTATUS="unknown"
      KREASON="fixed version for this distro is $fixed, but the installed package version could not be read"
    fi
    return
  fi

  if fixed="$(upstream_fixed_version "$br")"; then
    if version_ge "$base" "$fixed"; then
      KSTATUS="patched"; KREASON="upstream $base >= fixed $fixed"
    else
      KSTATUS="vulnerable"; KREASON="upstream $base < fixed $fixed"
    fi
    return
  fi

  if version_ge "$br" "7.3"; then
    KSTATUS="patched"; KREASON="kernel line $br is at or above 7.3"
    return
  fi

  local major="${br%%.*}" minor="${br#*.}"
  if [ "$major" -lt 4 ]; then
    KSTATUS="patched"; KREASON="kernel $base predates the affected range (4.4+)"
  elif [ "$major" -eq 4 ] || { [ "$major" -eq 5 ] && [ "$minor" -le 4 ]; }; then
    KSTATUS="vulnerable"; KREASON="kernel line $br is end-of-life upstream; no fixed release exists"
  else
    KSTATUS="unknown"; KREASON="no fixed version recorded for $DISTRO_ID kernel $base; treat as vulnerable"
  fi
}

mptcp_enabled() {
  [ -r /proc/sys/net/mptcp/enabled ] && cat /proc/sys/net/mptcp/enabled || printf 'na'
}

mptcp_listeners() {
  have ss || return 0
  ss -Mln 2>/dev/null | sed -n '2,$p'
}

nft_present() {
  have nft && nft list table "$NFT_TABLE_FAMILY" "$NFT_TABLE_NAME" >/dev/null 2>&1
}

ipt_present() {
  have iptables && iptables -t raw -C PREROUTING -p tcp -m u32 --u32 "0>>24&0xF=6:15" -m comment --comment "$IPT_COMMENT" -j DROP >/dev/null 2>&1
}

run() {
  if $DRY_RUN; then
    info "  [dry-run] $*"
  else
    "$@"
  fi
}

apply_nft() {
  if nft_present; then ok "nftables rule already present"; return 0; fi
  if $DRY_RUN; then
    info "  [dry-run] nft add table $NFT_TABLE_FAMILY $NFT_TABLE_NAME"
    info "  [dry-run] nft add chain ... prerouting priority -300"
    info "  [dry-run] nft add rule ... meta l4proto tcp ip hdrlength gt 5 counter drop"
    return 0
  fi
  nft add table "$NFT_TABLE_FAMILY" "$NFT_TABLE_NAME"
  nft "add chain $NFT_TABLE_FAMILY $NFT_TABLE_NAME pre { type filter hook prerouting priority -300; policy accept; }"
  nft add rule "$NFT_TABLE_FAMILY" "$NFT_TABLE_NAME" pre meta l4proto tcp ip hdrlength gt 5 counter drop
  if nft list table "$NFT_TABLE_FAMILY" "$NFT_TABLE_NAME" 2>/dev/null | grep -q 'hdrlength > 5'; then
    ok "nftables rule installed and verified"
  else
    fail "nftables rule installed but verification failed"; return 1
  fi
}

apply_iptables() {
  if ipt_present; then ok "iptables rule already present"; return 0; fi
  if $DRY_RUN; then
    info "  [dry-run] iptables -t raw -I PREROUTING 1 -p tcp -m u32 --u32 \"0>>24&0xF=6:15\" -m comment --comment $IPT_COMMENT -j DROP"
    return 0
  fi
  if have modprobe; then modprobe xt_u32 2>/dev/null || true; fi
  if iptables -t raw -I PREROUTING 1 -p tcp -m u32 --u32 "0>>24&0xF=6:15" -m comment --comment "$IPT_COMMENT" -j DROP; then
    ok "iptables rule installed"
  else
    fail "iptables insert failed; xt_u32 may be absent (RHEL 9/10 omit it). Use --method nft"
    return 1
  fi
}

apply_rule() {
  case "$METHOD" in
    nft) apply_nft ;;
    iptables) apply_iptables ;;
    auto)
      if have nft; then apply_nft
      elif have iptables; then apply_iptables
      else fail "neither nft nor iptables is available"; return 1
      fi ;;
  esac
}

remove_rule() {
  if nft_present; then
    run nft delete table "$NFT_TABLE_FAMILY" "$NFT_TABLE_NAME"
    ok "nftables table removed"
  fi
  if ipt_present; then
    run iptables -t raw -D PREROUTING -p tcp -m u32 --u32 "0>>24&0xF=6:15" -m comment --comment "$IPT_COMMENT" -j DROP
    ok "iptables rule removed"
  fi
  if ! nft_present && ! ipt_present; then ok "no mitigation rule present"; fi
}

disable_mptcp() {
  local prev
  prev="$(mptcp_enabled)"
  if [ "$prev" = "na" ]; then warn "MPTCP not built into this kernel; nothing to disable"; return 0; fi
  if [ "$prev" = "0" ]; then ok "MPTCP already disabled"; return 0; fi
  if $DRY_RUN; then
    info "  [dry-run] write net.mptcp.enabled=0 to $SYSCTL_DROPIN and apply"
    return 0
  fi
  mkdir -p "$STATE_DIR"
  [ -f "$STATE_DIR/mptcp.previous" ] || printf '%s\n' "$prev" > "$STATE_DIR/mptcp.previous"
  printf 'net.mptcp.enabled = 0\n' > "$SYSCTL_DROPIN"
  sysctl -q -p "$SYSCTL_DROPIN"
  ok "MPTCP disabled (existing listeners keep working until their service restarts)"
}

restore_mptcp() {
  [ -f "$SYSCTL_DROPIN" ] || return 0
  local prev="1"
  [ -f "$STATE_DIR/mptcp.previous" ] && prev="$(cat "$STATE_DIR/mptcp.previous")"
  if $DRY_RUN; then
    info "  [dry-run] restore net.mptcp.enabled=$prev and remove $SYSCTL_DROPIN"
    return 0
  fi
  rm -f "$SYSCTL_DROPIN"
  sysctl -q -w "net.mptcp.enabled=$prev" || true
  rm -f "$STATE_DIR/mptcp.previous"
  ok "MPTCP setting restored to $prev"
}

report() {
  local verbose="${1:-false}"
  detect_distro
  detect_container
  classify

  info "Host:        $(hostname)"
  info "Distro:      $DISTRO_NAME ($DISTRO_ID)"
  info "Kernel:      $KERNEL_REL"
  [ -n "$KERNEL_PKG" ] && info "Kernel pkg:  $KERNEL_PKG"
  if $IN_CONTAINER; then
    info "Container:   yes (kernel is the host's; check the host too)"
  fi
  info ""

  case "$KSTATUS" in
    patched)    info "Status:      PATCHED";;
    vulnerable) info "Status:      VULNERABLE";;
    *)          info "Status:      UNDETERMINED (treat as vulnerable)";;
  esac
  info "Reason:      $KREASON"
  info ""

  local mptcp; mptcp="$(mptcp_enabled)"
  info "MPTCP:       net.mptcp.enabled = $mptcp"
  local listeners; listeners="$(mptcp_listeners)"
  if [ -n "$listeners" ]; then
    info "MPTCP listeners:"
    printf '%s\n' "$listeners" | sed 's/^/             /'
  else
    info "MPTCP listeners: none"
  fi
  info "tcp_migrate_req: $(cat /proc/sys/net/ipv4/tcp_migrate_req 2>/dev/null || echo na)"
  info ""

  if nft_present; then ok "nftables mitigation present"
  elif ipt_present; then ok "iptables mitigation present"
  else info "Mitigation:  not installed"; fi

  if $verbose; then
    info ""
    info "Notes:"
    info "  - The trigger is an IPv4 TCP SYN carrying IP options; normal traffic never uses them."
    info "  - Bridged container traffic can bypass a prerouting rule on some setups."
    info "  - IPv6 is not affected by the primary issue."
  fi
}

require_root() {
  if [ "$(id -u)" -ne 0 ] && ! $DRY_RUN; then
    die "apply/remove need root; re-run with sudo (or add --dry-run)"
  fi
}

cmd_check() {
  detect_distro
  classify
  case "$KSTATUS" in
    patched) info "$KERNEL_REL: patched ($KREASON)"; exit 0 ;;
    vulnerable) info "$KERNEL_REL: VULNERABLE ($KREASON)"; exit 2 ;;
    *) info "$KERNEL_REL: undetermined, treat as vulnerable ($KREASON)"; exit 3 ;;
  esac
}

cmd_apply() {
  require_root
  detect_distro
  classify
  if [ "$KSTATUS" = "patched" ]; then
    ok "kernel is patched; no mitigation needed"
    exit 0
  fi
  info "Applying interim mitigation for $CVE on $KERNEL_REL ($KSTATUS)"
  apply_rule
  if $DISABLE_MPTCP; then disable_mptcp; fi
  info ""
  info "Done. Revert with: sudo $0 remove"
  info "Remove the rule after booting into a fixed kernel."
}

cmd_remove() {
  require_root
  remove_rule
  restore_mptcp
}

main() {
  while [ $# -gt 0 ]; do
    case "$1" in
      check|status|apply|remove) ACTION="$1"; shift ;;
      --method) METHOD="${2:-}"; shift 2 ;;
      --method=*) METHOD="${1#*=}"; shift ;;
      --disable-mptcp) DISABLE_MPTCP=true; shift ;;
      --dry-run) DRY_RUN=true; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown argument: $1 (try --help)" ;;
    esac
  done
  case "$METHOD" in auto|nft|iptables) ;; *) die "invalid --method: $METHOD" ;; esac
  [ "$(uname -s)" = "Linux" ] || die "this script reports the kernel it runs on; run it on each Linux host, not from $(uname -s)"
  case "$ACTION" in
    check)  cmd_check ;;
    status) report true ;;
    apply)  cmd_apply ;;
    remove) cmd_remove ;;
  esac
}

main "$@"
