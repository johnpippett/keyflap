# Keyflap's install progress, shared by install.sh (Linux and macOS) and the one-command
# installer (make-bootstrap.sh copies this file into install-keyflap.sh). Bash 3.2, BSD and GNU
# tools. Defines functions only.
#
# On a terminal (stdout a TTY, TERM set and not dumb) it draws, in place, the brand's setup
# header: the K tile and KEYFLAP, one thin bar, and the step in progress next to a flipping
# tile; the script's own output and its commands' output go to a root-only install log, and
# the screen ends with a short summary. Without a terminal it prints the plain `==>` lines, as
# before. Colour follows the brand's CLI rules: 24-bit only with COLORTERM, else 256 colours
# when TERM says so, else 16; none with NO_COLOR.
#
#   progress_init SUBTITLE          choose the view (pg_view=1) or plain lines (pg_view=0)
#   progress_note TEXT              a detail line: stdout without the view, the log with it
#   progress_start TOTAL LOG [TO]   open LOG (its directory must be root-only) and draw; the
#                                   steps fill the bar up to TO per mille (default 1000)
#   progress_step LABEL PLAIN       the next step: LABEL on screen, `==> PLAIN` in plain and log
#   progress_watch KIND FILE        the current step's progress: curl's meter or Playwright's
#   progress_warn TEXT              a line for the summary, marked `!`
#   progress_finish TITLE           the final frame and the warnings; gives the terminal back
#   progress_hand_over LABEL        leave the frame at TO, showing LABEL, for the next script
#   progress_say TEXT               a line under the frame at column 5, wrapped at word breaks to
#                                   the terminal (a `N) ` item's next lines hang under its text)
#   progress_fail MESSAGE           the error, in full, under a stopped frame (or plain stderr)
#   progress_exit CODE              from the EXIT trap: a stop nobody explained, and cleanup
#
# KEYFLAP_PROGRESS_FROM=N (0-999) continues the frame the calling script left on screen, from N
# per mille of the bar (a new frame instead once the script sets pg_in_place=0, after a prompt);
# the one-command installer sets it for install.sh.

pg_view=0 pg_active=0 pg_drawn=0 pg_in_place=1 pg_log_shown=1 pg_rows=6 pg_cols=80 pg_width=60 pg_sub='' pg_log='' pg_dir=''
pg_notes='' pg_warns='' pg_ticker='' pg_stty='' pg_n=0 pg_total=1 pg_from=0 pg_to=1000 pg_label='' pg_watch=''
pg_kind='' pg_ok='' pg_ok_end='' pg_tile='' pg_dim='' pg_dim_end='' pg_bold='' pg_bold_end=''
pg_bad='' pg_bad_end='' pg_reset=''

progress_init() {
  pg_sub=$1
  pg_view=0
  [ -t 1 ] || return 0
  case ${TERM:-dumb} in dumb) return 0 ;; esac
  { : </dev/tty; } 2>/dev/null || return 0
  local size
  size=$(stty size </dev/tty 2>/dev/null) || size=''
  pg_cols=${size##* }
  case $pg_cols in "" | 0 | *[!0-9]*) pg_cols=80 ;; esac
  [ "$pg_cols" -ge 30 ] || return 0
  pg_width=$((pg_cols - 7))
  [ $pg_width -le 76 ] || pg_width=76
  pg_styles
  pg_view=1
}

pg_styles() {
  local level=1 light=0 e=$'\033['
  if [ -n "${NO_COLOR:-}" ]; then
    level=0
  elif [ "${COLORTERM:-}" = truecolor ] || [ "${COLORTERM:-}" = 24bit ]; then
    level=3
  else
    case ${TERM:-} in *256col*) level=2 ;; esac
  fi
  case ${COLORFGBG:-} in *';7' | *';15') light=1 ;; esac
  [ $level -gt 0 ] || return 0
  case $level$light in
    30) pg_ok="${e}38;2;123;145;255m" ;;
    31) pg_ok="${e}38;2;31;59;209m" ;;
    20) pg_ok="${e}38;5;105m" ;;
    21) pg_ok="${e}38;5;26m" ;;
    10) pg_ok="${e}94m" ;;
    11) pg_ok="${e}34m" ;;
  esac
  case $level in
    3) pg_tile="${e}48;2;31;59;209;38;2;244;245;247;1m" ;;
    2) pg_tile="${e}48;5;26;38;5;231;1m" ;;
    1) pg_tile="${e}44;97;1m" ;;
  esac
  pg_ok_end="${e}39m"
  pg_dim="${e}2m" pg_dim_end="${e}22m"
  pg_bold="${e}1m" pg_bold_end="${e}22m"
  pg_bad="${e}7;1m" pg_bad_end="${e}27;22m"
  pg_reset="${e}0m"
}

pg_tile_of() {
  if [ -n "$pg_tile" ]; then printf '%s %s %s' "$pg_tile" "$1" "$pg_reset"; else printf '[%s]' "$1"; fi
}

pg_repeat() {
  local out='' i=0
  while [ $i -lt "$2" ]; do out=$out$1; i=$((i + 1)); done
  printf '%s' "$out"
}

progress_note() {
  if [ $pg_view -eq 0 ] || [ $pg_active -eq 1 ]; then
    printf '%s\n' "$*"
  else
    pg_notes="$pg_notes$*
"
  fi
}

progress_warn() {
  pg_warns="$pg_warns$*
"
}

# progress_start TOTAL LOG: from here on stdout and stderr go to LOG (created 0600 by root in a
# directory only root can change), and the screen shows the frame.
progress_start() {
  pg_total=$1
  pg_log=$2
  pg_to=${3:-1000}
  [ $pg_view -eq 1 ] || return 0
  [ ! -L "$pg_log" ] || rm -f "$pg_log"
  (umask 077 && : >>"$pg_log")
  chmod 0600 "$pg_log"
  pg_dir=$(mktemp -d "${TMPDIR:-/tmp}/keyflap-progress.XXXXXX")
  exec 7>&1 8>&2 1>>"$pg_log" 2>&1
  printf '\n==== %s, %s\n' "$pg_sub" "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  [ -z "$pg_notes" ] || printf '%s' "$pg_notes"
  pg_notes=''
  pg_from=0
  case ${KEYFLAP_PROGRESS_FROM:-} in
    [0-9] | [0-9][0-9] | [0-9][0-9][0-9]) pg_from=$KEYFLAP_PROGRESS_FROM pg_drawn=$pg_in_place ;;
  esac
  pg_stty=$(stty -g </dev/tty 2>/dev/null) || pg_stty=''
  [ -z "$pg_stty" ] || stty -echo </dev/tty 2>/dev/null || true
  printf '\033[?25l' >&7
  trap 'exit 130' INT
  trap 'exit 143' TERM
  pg_active=1
  pg_n=0
}

progress_step() {
  if [ $pg_view -eq 0 ]; then
    [ -z "$2" ] || printf '==> %s\n' "$2"
    return 0
  fi
  [ -z "$2" ] || progress_note "==> $2"
  [ -n "$1" ] || return 0
  pg_n=$((pg_n + 1))
  [ $pg_n -le $pg_total ] || pg_total=$pg_n
  pg_label=$1
  pg_watch=''
  pg_kind=''
  [ $pg_active -eq 1 ] || return 0
  printf -- '-- step %s of %s: %s\n' "$pg_n" "$pg_total" "$1"
  pg_state
  [ -z "$pg_ticker" ] || return 0
  pg_frame 0 >&7
  pg_drawn=1
  pg_tick &
  pg_ticker=$!
}

progress_watch() {
  [ $pg_active -eq 1 ] || return 0
  pg_kind=$1
  pg_watch=$2
  pg_state
}

pg_state() {
  printf '%s\n%s\n%s\n%s\n%s\n' "$pg_n" "$pg_total" "$pg_label" "$pg_kind" "$pg_watch" >"$pg_dir/state.tmp"
  mv "$pg_dir/state.tmp" "$pg_dir/state"
}

pg_tick() {
  local parent=$$ i=1
  while [ ! -f "$pg_dir/stop" ] && kill -0 "$parent" 2>/dev/null; do
    pg_frame $i >&7
    i=$((i + 1))
    sleep 0.12
  done
  : >"$pg_dir/stopped"
}

# pg_measure KIND FILE: "PERCENT DETAIL" from a download's own progress output, or nothing.
pg_measure() {
  [ -s "$2" ] || return 0
  case $1 in
    curl)
      tr '\r' '\n' <"$2" | awk '
        function mb(v,  u) {
          u = substr(v, length(v)); if (u ~ /[0-9]/) return v / 1048576
          v = substr(v, 1, length(v) - 1)
          if (u == "k") return v / 1024; if (u == "M") return v; if (u == "G") return v * 1024
          return v / 1048576
        }
        NF >= 4 && $1 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ { p = $1; t = $2; r = $4 }
        END {
          if (p == "" || mb(t) <= 0) exit
          if (mb(t) < 1) printf "%d %d of %d KB\n", p, mb(r) * 1024, mb(t) * 1024
          else printf "%d %.1f of %.1f MB\n", p, mb(r), mb(t)
        }' ;;
    playwright)
      awk '
        /[0-9]+% of [0-9.]+ MiB/ {
          for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+%$/ && $(i + 1) == "of") { p = $i + 0; t = $(i + 2) }
        }
        END { if (p != "") printf "%d %.1f of %.1f MB\n", p, p * t / 100, t }' "$2" ;;
  esac
}

pg_bar() {
  local done=$(($1 * pg_width / 1000))
  printf '     %s%s%s%s%s%s' "$pg_ok" "$(pg_repeat '━' $done)" "$pg_ok_end" \
    "$pg_dim" "$(pg_repeat '─' $((pg_width - done)))" "$pg_dim_end"
}

pg_header() {
  printf ' %s %sKEYFLAP%s  %s%s%s' "$(pg_tile_of K)" "$pg_bold" "$pg_bold_end" "$pg_dim" "$pg_sub" "$pg_dim_end"
}

# pg_frame TICK: the whole frame as one write, starting from its first line.
pg_frame() {
  local n=0 total=1 label='' kind='' file='' pct=0 detail='' m spin permille pad up=''
  if [ -f "$pg_dir/state" ]; then
    { read -r n; read -r total; read -r label; read -r kind; read -r file; } <"$pg_dir/state"
  fi
  if [ -n "$kind" ]; then
    m=$(pg_measure "$kind" "$file")
    if [ -n "$m" ]; then pct=${m%% *}; detail=${m#* }; fi
  fi
  [ "$n" -ge 1 ] || n=1
  permille=$((pg_from + (pg_to - pg_from) * ((n - 1) * 100 + pct) / (total * 100)))
  case $(($1 % 4)) in 0) spin='▀' ;; 1 | 3) spin='▬' ;; 2) spin='▄' ;; esac
  pad=$((pg_width - ${#label} - ${#detail}))
  [ $pad -ge 2 ] && [ -n "$detail" ] || { detail=''; pad=0; }
  [ $pg_drawn -eq 0 ] || up=$'\r\033['$pg_rows'A'
  printf '%s\033[2K\n\033[2K%s\n\033[2K%s\n\033[2K\n\033[2K %s %s%s%s%s%s\n\033[2K\n' "$up" \
    "$(pg_header)" "$(pg_bar $permille)" "$(pg_tile_of "$spin")" "$label" \
    "$(pg_repeat ' ' $pad)" "$pg_dim" "$detail" "$pg_dim_end"
}

pg_stop_ticker() {
  local i=0
  [ -n "$pg_ticker" ] || return 0
  : >"$pg_dir/stop"
  while [ ! -f "$pg_dir/stopped" ] && [ $i -lt 40 ]; do
    sleep 0.05
    i=$((i + 1))
  done
  wait "$pg_ticker" 2>/dev/null || true
  pg_ticker=''
}

# pg_end MARK TITLE PERMILLE: the last frame, then the terminal and stdout/stderr back as they were.
pg_end() {
  local up=''
  pg_stop_ticker
  [ $pg_drawn -eq 0 ] || up=$'\r\033['$pg_rows'A'
  printf '%s\033[2K\n\033[2K%s\n\033[2K%s\n\033[2K\n\033[2K%s%s\n\033[2K\n' "$up" "$(pg_header)" \
    "$(pg_bar "$3")" "$1" "$2" >&7
  printf '\033[?25h' >&7
  [ -z "$pg_stty" ] || stty "$pg_stty" </dev/tty 2>/dev/null || true
  exec 1>&7 2>&8 7>&- 8>&-
  pg_active=0
}

pg_warnings() {
  [ -n "$pg_warns" ] || return 0
  printf '%s\n' "$pg_warns" | while IFS= read -r w; do
    [ -z "$w" ] || printf '   %s!%s %s\n' "$pg_bold" "$pg_bold_end" "$w"
  done
  printf '\n'
}

progress_finish() {
  [ $pg_active -eq 1 ] || return 0
  printf '==== done: %s\n' "$1"
  pg_end "   $pg_ok✓$pg_ok_end " "$1" 1000
  pg_warnings
}

progress_hand_over() {
  [ $pg_active -eq 1 ] || return 0
  pg_end " $(pg_tile_of '▀') " "$1" "$pg_to"
}

progress_say() {
  if [ -z "$*" ]; then
    printf '\n'
    return 0
  fi
  printf '%s\n' "$*" | awk -v cols="$pg_cols" '
    {
      match($0, /^ */)
      lead = substr($0, 1, RLENGTH)
      hang = lead
      if (substr($0, RLENGTH + 1) ~ /^[0-9]\) /) hang = lead "   "
      width = cols - 6 - length(hang)
      if (width < 20) width = 20
      n = split($0, word, " ")
      line = ""
      out = 0
      for (i = 1; i <= n; i++) {
        if (line == "") line = word[i]
        else if (length(line) + 1 + length(word[i]) <= width) line = line " " word[i]
        else {
          print "     " (out++ ? hang : lead) line
          line = word[i]
        }
      }
      print "     " (out ? hang : lead) line
    }'
}

pg_failed_mark() {
  if [ -n "$pg_bad" ]; then printf '  %s ✗ %s' "$pg_bad" "$pg_bad_end"; else printf '   ✗ '; fi
}

progress_fail() {
  if [ $pg_active -eq 0 ]; then
    printf '%s\n' "$1" >&2
    return 0
  fi
  printf '%s\n' "$1"
  : >"$pg_dir/failed"
  local permille=$((pg_from + (pg_to - pg_from) * (pg_n > 0 ? pg_n - 1 : 0) / pg_total))
  pg_end "$(pg_failed_mark)" "${pg_label:-Starting}" $permille
  printf '%s\n' "$1" >&2
  [ $pg_log_shown -eq 0 ] || printf '\n     Details: %s\n' "$pg_log" >&2
}

progress_exit() {
  if [ $pg_active -eq 1 ] && [ -f "$pg_dir/failed" ]; then
    printf '\033[?25h' >&7
    [ -z "$pg_stty" ] || stty "$pg_stty" </dev/tty 2>/dev/null || true
  elif [ $pg_active -eq 1 ]; then
    if [ "$1" -eq 130 ] || [ "$1" -eq 143 ]; then
      progress_fail "Stopped before the end. Run the same command again to finish."
    else
      local tail
      tail=$(tail -n 12 "$pg_log" 2>/dev/null | sed 's/^/  /')
      progress_fail "Stopped: a command failed (exit $1). Its last lines:
$tail"
    fi
  fi
  [ -z "$pg_dir" ] || rm -rf "$pg_dir"
  return 0
}

# keyflap_install_log OS: where root keeps the install log (darwin or linux).
keyflap_install_log() {
  case $1 in
    darwin) printf '/Library/Keyflap/log/install.log' ;;
    *) printf '/var/log/keyflap/install.log' ;;
  esac
}
