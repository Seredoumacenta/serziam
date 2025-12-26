#!/bin/bash
# security_intelligence_platform.sh - Plateforme complète d'analyse de sécurité
# Version: 3.0 | Date: $(date +%Y-%m-%d) | Compatible: Termux/Ubuntu

# ==============================================================================
# CONFIGURATION GLOBALE
# ==============================================================================

# Couleurs ANSI professionnelles
readonly COLOR_RESET="\033[0m"
readonly COLOR_GREEN="\033[1;32m"
readonly COLOR_RED="\033[1;31m"
readonly COLOR_YELLOW="\033[1;33m"
readonly COLOR_BLUE="\033[1;34m"
readonly COLOR_CYAN="\033[1;36m"
readonly COLOR_MAGENTA="\033[1;35m"
readonly COLOR_WHITE="\033[1;37m"
readonly COLOR_BG_GREEN="\033[42m\033[30m"
readonly COLOR_BG_RED="\033[41m\033[30m"
readonly COLOR_BG_BLUE="\033[44m\033[37m"

# Configuration principale
readonly SCRIPT_NAME="Security Intelligence Platform"
readonly SCRIPT_VERSION="3.0"
readonly AUTHOR="SecOps Team"
readonly LICENSE="GPL-3.0"

# Variables globales
ROOT_DOMAIN="${1}"
BASE_OUTPUT_DIR="./sip_audit_$(date +%Y%m%d)"
REPORT_DIR="${BASE_OUTPUT_DIR}/reports"
LOG_DIR="${BASE_OUTPUT_DIR}/logs"
DATA_DIR="${BASE_OUTPUT_DIR}/data"
CONFIG_DIR="${BASE_OUTPUT_DIR}/config"
BIN_DIR="${BASE_OUTPUT_DIR}/bin"

# Seuils configurables
DNS_SLOW_THRESHOLD=500
DNS_CRITICAL_THRESHOLD=1000
TLS_WARNING_LEVEL="TLSv1.1"
HTTP_TIMEOUT=10
MAX_SUBDOMAINS=1000

# Fichiers de configuration
readonly CONFIG_FILE="${CONFIG_DIR}/sip_config.conf"
readonly WORDLIST_FILE="${CONFIG_DIR}/wordlist.txt"
readonly TLD_FILE="${CONFIG_DIR}/tld_list.txt"

# ==============================================================================
# MODULE: INITIALISATION ET UTILITAIRES
# ==============================================================================

init_system() {
    echo -e "${COLOR_BG_BLUE}════════════════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${COLOR_WHITE}           SECURITY INTELLIGENCE PLATFORM v${SCRIPT_VERSION}           ${COLOR_RESET}"
    echo -e "${COLOR_BG_BLUE}════════════════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${COLOR_CYAN}Date: $(date)${COLOR_RESET}"
    echo -e "${COLOR_CYAN}Target: ${ROOT_DOMAIN}${COLOR_RESET}"
    echo ""
    
    # Création de l'arborescence
    mkdir -p {"$REPORT_DIR","$LOG_DIR","$DATA_DIR","$CONFIG_DIR","$BIN_DIR"}/{tls,websocket,dns,sni,ports,proxy,cache}
    
    # Fichiers de base
    > "${LOG_DIR}/sip_execution.log"
    > "${LOG_DIR}/errors.log"
    
    # Chargement de la configuration
    load_configuration
    check_environment
}

load_configuration() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
    else
        create_default_config
    fi
}

create_default_config() {
    cat > "$CONFIG_FILE" << EOF
# Configuration SIP v${SCRIPT_VERSION}
# Généré le: $(date)

# Performances
DNS_SLOW_THRESHOLD=500
DNS_CRITICAL_THRESHOLD=1000
HTTP_TIMEOUT=10
MAX_THREADS=50

# Sécurité
ENABLE_PROXY=false
PROXY_HOST="127.0.0.1"
PROXY_PORT=8080
ENABLE_TOR=false

# Recherche
WORDLIST_SOURCE="builtin"
ENABLE_BRUTEFORCE=true
BRUTEFORCE_LEVEL="normal"
ENABLE_PASSIVE=true

# Reporting
REPORT_FORMAT="markdown"
ENABLE_DASHBOARD=true
COMPRESS_RESULTS=true

# Notifications
ENABLE_NOTIFICATIONS=false
NOTIFICATION_EMAIL=""
EOF

    # Création de la wordlist
    cat > "$WORDLIST_FILE" << EOF
www
mail
api
blog
test
dev
staging
prod
admin
secure
web
app
mobile
portal
cdn
shop
store
forum
support
help
docs
wiki
status
monitor
analytics
dashboard
login
auth
oauth
sso
graphql
rest
soap
ftp
sftp
ssh
rdp
vpn
git
svn
jenkins
docker
registry
kubernetes
aws
azure
gcp
cloud
storage
db
mysql
postgres
mongodb
redis
elastic
kibana
grafana
prometheus
alertmanager
EOF
}

check_environment() {
    local -a required_tools=("dig" "curl" "openssl" "nmap" "whois" "python3")
    local -a optional_tools=("masscan" "amass" "subfinder" "httpx" "nuclei" "gobuster")
    
    echo -e "${COLOR_BLUE}[*] Vérification de l'environnement...${COLOR_RESET}"
    
    # Détection de la plateforme
    if [[ -d "/data/data/com.termux/files/usr" ]]; then
        PLATFORM="Termux"
        PACKAGE_MANAGER="pkg"
    elif command -v apt &>/dev/null; then
        PLATFORM="Ubuntu/Debian"
        PACKAGE_MANAGER="apt"
    elif command -v yum &>/dev/null; then
        PLATFORM="RHEL/CentOS"
        PACKAGE_MANAGER="yum"
    else
        PLATFORM="Unknown"
        PACKAGE_MANAGER=""
    fi
    
    echo -e "  ${COLOR_GREEN}✓${COLOR_RESET} Plateforme: $PLATFORM"
    
    # Vérification des outils requis
    local missing_required=()
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_required+=("$tool")
        fi
    done
    
    if [[ ${#missing_required[@]} -gt 0 ]]; then
        echo -e "  ${COLOR_RED}✗${COLOR_RESET} Outils manquants: ${missing_required[*]}"
        install_tools "${missing_required[@]}"
    fi
    
    echo -e "${COLOR_GREEN}[+] Environnement vérifié avec succès${COLOR_RESET}"
}

install_tools() {
    local tools=("$@")
    
    echo -e "${COLOR_YELLOW}[!] Installation des outils manquants...${COLOR_RESET}"
    
    for tool in "${tools[@]}"; do
        case "$tool" in
            "dig")        install_package "dnsutils" ;;
            "curl")       install_package "curl" ;;
            "openssl")    install_package "openssl" ;;
            "nmap")       install_package "nmap" ;;
            "whois")      install_package "whois" ;;
            "python3")    install_package "python3" ;;
            *)            echo "  Outil non reconnu: $tool" ;;
        esac
    done
}

install_package() {
    local package="$1"
    
    case "$PACKAGE_MANAGER" in
        "pkg")   pkg install -y "$package" 2>> "${LOG_DIR}/installation.log" ;;
        "apt")   sudo apt update && sudo apt install -y "$package" 2>> "${LOG_DIR}/installation.log" ;;
        "yum")   sudo yum install -y "$package" 2>> "${LOG_DIR}/installation.log" ;;
    esac
    
    if [[ $? -eq 0 ]]; then
        echo -e "  ${COLOR_GREEN}✓${COLOR_RESET} Installé: $package"
    else
        echo -e "  ${COLOR_RED}✗${COLOR_RESET} Échec installation: $package"
    fi
}

# ==============================================================================
# MODULE: LOGGING ET RAPPORTING
# ==============================================================================

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")    echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $message" ;;
        "SUCCESS") echo -e "${COLOR_GREEN}[✓]${COLOR_RESET} $message" ;;
        "WARNING") echo -e "${COLOR_YELLOW}[!]${COLOR_RESET} $message" ;;
        "ERROR")   echo -e "${COLOR_RED}[✗]${COLOR_RESET} $message" ;;
        "CRITICAL") echo -e "${COLOR_BG_RED}[CRITICAL]${COLOR_RESET} $message" ;;
        "BUG")     echo -e "${COLOR_BG_GREEN}[BUG]${COLOR_RESET} $message" ;;
        "DEBUG")   [[ "$DEBUG" == "true" ]] && echo -e "${COLOR_MAGENTA}[DEBUG]${COLOR_RESET} $message" ;;
    esac | tee -a "${LOG_DIR}/sip_execution.log"
}

save_result() {
    local category="$1"
    local subdomain="$2"
    local data="$3"
    
    local safe_name=$(echo "$subdomain" | tr './' '_')
    echo "$data" >> "${DATA_DIR}/${category}/${safe_name}.json"
}

generate_report() {
    local report_type="$1"
    
    case "$report_type" in
        "executive")
            generate_executive_report
            ;;
        "technical")
            generate_technical_report
            ;;
        "comprehensive")
            generate_comprehensive_report
            ;;
        "dashboard")
            generate_dashboard
            ;;
    esac
}

# ==============================================================================
# MODULE: DÉCOUVERTE DE RESSOURCES
# ==============================================================================

discover_all_assets() {
    log "INFO" "Phase 1: Découverte complète des actifs"
    
    # Sous-domaines
    discover_subdomains_ct
    discover_subdomains_dns
    discover_subdomains_bruteforce
    discover_subdomains_certificates
    discover_subdomains_web
    
    # IPs et réseaux
    discover_ip_addresses
    discover_network_ranges
    discover_dns_records
    
    # Services et technologies
    discover_technologies
    discover_cloud_assets
    
    log "SUCCESS" "Découverte terminée"
}

discover_subdomains_ct() {
    log "INFO" "Recherche via Certificate Transparency"
    
    local sources=(
        "https://crt.sh/?q=%25.${ROOT_DOMAIN}&output=json"
        "https://api.certspotter.com/v1/issuances?domain=${ROOT_DOMAIN}&include_subdomains=true&expand=dns_names"
        "https://tls.bufferover.run/dns?q=.${ROOT_DOMAIN}"
    )
    
    for source in "${sources[@]}"; do
        curl -s "$source" 2>/dev/null | \
            grep -oE '[a-zA-Z0-9._-]+' | \
            grep -i "${ROOT_DOMAIN}" | \
            sort -u >> "${DATA_DIR}/subdomains_ct.txt"
    done
}

discover_subdomains_dns() {
    log "INFO" "Recherche via DNS"
    
    # Transfert de zone
    dig AXFR "@ns1.${ROOT_DOMAIN}" "${ROOT_DOMAIN}" 2>/dev/null | \
        grep -E "^[a-zA-Z0-9._-]+" >> "${DATA_DIR}/subdomains_dns.txt"
    
    # Recherche récursive
    for type in A AAAA MX NS TXT CNAME; do
        dig "${ROOT_DOMAIN}" "$type" +short 2>/dev/null | \
            grep -E "[a-zA-Z0-9._-]+\." >> "${DATA_DIR}/subdomains_dns.txt"
    done
}

discover_subdomains_bruteforce() {
    log "INFO" "Recherche par brute-force"
    
    local wordlist=("www" "api" "admin" "test" "dev" "staging" "prod" "mail" "blog")
    
    for word in "${wordlist[@]}"; do
        for tld in com net org io co; do
            dig "${word}.${ROOT_DOMAIN}.${tld}" A +short 2>/dev/null | \
                grep -q . && echo "${word}.${ROOT_DOMAIN}.${tld}" || continue
        done &
    done | sort -u > "${DATA_DIR}/subdomains_brute.txt"
    wait
}

# ==============================================================================
# MODULE: ANALYSE DE SÉCURITÉ
# ==============================================================================

perform_security_analysis() {
    log "INFO" "Phase 2: Analyse de sécurité complète"
    
    # Analyse réseau
    analyze_ports_and_services
    analyze_dns_security
    analyze_ssl_tls
    analyze_http_headers
    analyze_web_security
    
    # Tests de vulnérabilités
    test_common_vulnerabilities
    test_web_application_security
    test_api_security
    test_infrastructure_security
    
    log "SUCCESS" "Analyse de sécurité terminée"
}

analyze_ssl_tls() {
    log "INFO" "Analyse SSL/TLS approfondie"
    
    while read -r target; do
        [[ -z "$target" ]] && continue
        
        local result_file="${DATA_DIR}/tls/${target//./_}.json"
        
        # Test complet SSL
        local ssl_test=$(timeout 10 openssl s_client -connect "${target}:443" \
            -servername "$target" -tls1_3 -tlsextdebug -status 2>&1)
        
        local issues=()
        
        # Détection de bugs
        check_ssl_bugs "$ssl_test" "$target"
        
        # Enregistrement
        cat > "$result_file" << EOF
{
  "target": "$target",
  "timestamp": "$(date -Iseconds)",
  "issues": $(printf '%s\n' "${issues[@]}" | jq -R . | jq -s .),
  "raw_output": "$(echo "$ssl_test" | jq -Rsa .)"
}
EOF
        
    done < <(grep -E "https?://" "${DATA_DIR}/all_targets.txt" | head -50)
}

check_ssl_bugs() {
    local output="$1"
    local target="$2"
    local -n issues_ref="$3"
    
    # Certificat expiré
    if echo "$output" | grep -q "certificate has expired"; then
        issues_ref+=("CERTIFICAT_EXPIRÉ")
        log "BUG" "${COLOR_GREEN}Certificat expiré sur ${target}${COLOR_RESET}"
    fi
    
    # Chaîne incomplète
    if echo "$output" | grep -q "verify error"; then
        issues_ref+=("CHAÎNE_INCOMPLÈTE")
        log "BUG" "${COLOR_GREEN}Chaîne de certificats incomplète sur ${target}${COLOR_RESET}"
    fi
    
    # Weak cipher
    if echo "$output" | grep -q "RC4\|DES\|MD5\|SHA1"; then
        issues_ref+=("CHIFFREMENT_FAIBLE")
        log "BUG" "${COLOR_GREEN}Chiffrement faible sur ${target}${COLOR_RESET}"
    fi
    
    # SNI bug
    check_sni_bug "$target"
}

check_sni_bug() {
    local target="$1"
    
    local valid_sni=$(openssl s_client -connect "${target}:443" \
        -servername "$target" 2>&1 | grep -i "subject=")
    
    local invalid_sni=$(openssl s_client -connect "${target}:443" \
        -servername "invalid.test.${target}" 2>&1 | grep -i "subject=")
    
    if [[ "$valid_sni" == "$invalid_sni" ]]; then
        log "BUG" "${COLOR_GREEN}Bug SNI détecté sur ${target}${COLOR_RESET}"
        return 1
    fi
    
    return 0
}

analyze_dns_security() {
    log "INFO" "Analyse de sécurité DNS"
    
    while read -r domain; do
        # DNSSEC validation
        dig "$domain" +dnssec +short | grep -q "RRSIG" && \
            echo "DNSSEC activé: $domain" || \
            log "BUG" "${COLOR_GREEN}DNSSEC non activé: ${domain}${COLOR_RESET}"
        
        # DNS zone transfer
        dig AXFR "@ns1.${domain}" "$domain" 2>&1 | grep -q "Transfer failed" || \
            log "BUG" "${COLOR_GREEN}Transfert de zone possible: ${domain}${COLOR_RESET}"
        
        # Slow DNS detection
        measure_dns_response "$domain"
        
    done < "${DATA_DIR}/all_domains.txt"
}

measure_dns_response() {
    local domain="$1"
    
    for i in {1..3}; do
        local start=$(date +%s%N)
        dig "$domain" A +short >/dev/null 2>&1
        local end=$(date +%s%N)
        local duration=$(( (end - start) / 1000000 ))
        
        if [[ $duration -gt $DNS_SLOW_THRESHOLD ]]; then
            log "BUG" "${COLOR_GREEN}SlowDNS détecté: ${domain} (${duration}ms)${COLOR_RESET}"
            echo "$domain,$duration" >> "${DATA_DIR}/slow_dns.csv"
            break
        fi
    done
}

# ==============================================================================
# MODULE: WEB SOCKET ANALYSIS
# ==============================================================================

analyze_websocket_security() {
    log "INFO" "Analyse de sécurité WebSocket"
    
    while read -r url; do
        [[ -z "$url" ]] && continue
        
        # Test WebSocket basic
        local ws_test=$(timeout 10 curl -i -s \
            -H "Connection: Upgrade" \
            -H "Upgrade: websocket" \
            -H "Sec-WebSocket-Version: 13" \
            "$url" 2>&1)
        
        # Détection de vulnérabilités
        check_websocket_bugs "$ws_test" "$url"
        
    done < <(grep -E "^https?://" "${DATA_DIR}/web_targets.txt" | head -30)
}

check_websocket_bugs() {
    local response="$1"
    local url="$2"
    
    # CORS misconfiguration
    if echo "$response" | grep -q "Access-Control-Allow-Origin: *"; then
        log "BUG" "${COLOR_GREEN}CORS trop permissif sur ${url}${COLOR_RESET}"
    fi
    
    # Missing security headers
    if ! echo "$response" | grep -qi "Sec-WebSocket-Accept"; then
        log "BUG" "${COLOR_GREEN}Header Sec-WebSocket-Accept manquant sur ${url}${COLOR_RESET}"
    fi
    
    # Authentication issues
    if echo "$response" | grep -q "101" && \
       ! echo "$response" | grep -qi "www-authenticate\|authorization"; then
        log "BUG" "${COLOR_GREEN}WebSocket sans authentification sur ${url}${COLOR_RESET}"
    fi
}

# ==============================================================================
# MODULE: PROXY INTEGRATION
# ==============================================================================

setup_proxy_analysis() {
    log "INFO" "Configuration de l'analyse via proxy"
    
    local proxy_port=8888
    local proxy_host="127.0.0.1"
    
    # Démarrer mitmproxy
    if command -v mitmdump &>/dev/null; then
        mitmdump -p "$proxy_port" \
            --set save_stream_file="${DATA_DIR}/proxy/traffic.log" \
            --mode regular \
            --ssl-insecure \
            > "${LOG_DIR}/mitmproxy.log" 2>&1 &
        
        PROXY_PID=$!
        sleep 5
        
        # Tester le proxy
        if curl -s --proxy "http://${proxy_host}:${proxy_port}" \
               "http://httpbin.org/ip" >/dev/null 2>&1; then
            export HTTP_PROXY="http://${proxy_host}:${proxy_port}"
            export HTTPS_PROXY="http://${proxy_host}:${proxy_port}"
            log "SUCCESS" "Proxy configuré sur ${proxy_host}:${proxy_port}"
        else
            log "ERROR" "Échec de démarrage du proxy"
        fi
    else
        log "WARNING" "mitmproxy non installé, proxy désactivé"
    fi
}

analyze_through_proxy() {
    local url="$1"
    
    curl -s -I --proxy "$HTTP_PROXY" "$url" 2>/dev/null | \
        while read -r header; do
            # Analyse des headers via proxy
            analyze_header "$header" "$url"
        done
}

# ==============================================================================
# MODULE: REPORTING AVANCÉ
# ==============================================================================

generate_comprehensive_report() {
    log "INFO" "Génération du rapport complet"
    
    local report_file="${REPORT_DIR}/comprehensive_report_$(date +%Y%m%d).md"
    
    cat > "$report_file" << EOF
# RAPPORT COMPLET DE SÉCURITÉ
## Plateforme: ${SCRIPT_NAME} v${SCRIPT_VERSION}
## Cible: ${ROOT_DOMAIN}
## Date: $(date)
## Audit ID: $(uuidgen)

## EXÉCUTIF SUMMARY

### Métriques Clés
$(generate_metrics_table)

### Risques Identifiés
$(generate_risk_summary)

### Recommandations Prioritaires
$(generate_recommendations)

## DÉTAIL DES ANALYSES

### 1. Inventaire des Actifs
$(generate_asset_inventory)

### 2. Vulnérabilités SSL/TLS
$(generate_tls_vulnerabilities)

### 3. Problèmes DNS
$(generate_dns_issues)

### 4. Sécurité Web
$(generate_web_security)

### 5. Performance Réseau
$(generate_network_performance)

### 6. Bugs Détectés (Prioritaires)
$(generate_bugs_list)

## ANNEXES

### Commandes Exécutées
\`\`\`
$(tail -50 "${LOG_DIR}/sip_execution.log")
\`\`\`

### Configuration Utilisée
\`\`\`
$(cat "$CONFIG_FILE")
\`\`\`

### Fichiers Générés
\`\`\`
$(find "$BASE_OUTPUT_DIR" -type f | wc -l) fichiers dans $BASE_OUTPUT_DIR
\`\`\`

---
*Généré automatiquement par ${SCRIPT_NAME} v${SCRIPT_VERSION}*
*Confidential - Usage interne uniquement*
EOF
    
    log "SUCCESS" "Rapport généré: $report_file"
}

generate_metrics_table() {
    cat << EOF
| Catégorie | Total | Critiques | Haut | Moyen | Bas |
|-----------|-------|-----------|------|-------|-----|
| Sous-domaines | $(count_subdomains) | - | - | - | - |
| Vulnérabilités SSL/TLS | $(count_tls_vulns) | $(count_critical_tls) | - | - | - |
| SlowDNS | $(count_slow_dns) | $(count_critical_slow_dns) | - | - | - |
| Problèmes WebSocket | $(count_websocket_issues) | - | - | - | - |
| Bugs SNI | $(count_sni_bugs) | - | - | - | - |
EOF
}

generate_bugs_list() {
    echo "### Bugs avec En-têtes Verts"
    echo ""
    
    grep -h "\[BUG\]" "${LOG_DIR}/sip_execution.log" | \
        sed 's/.*\[BUG\] //' | \
        sort -u | \
        while read -r bug; do
            echo "1. **${bug}**"
            echo "   - Catégorie: $(echo "$bug" | cut -d: -f1)"
            echo "   - Impact: $(assess_bug_impact "$bug")"
            echo "   - Recommandation: $(generate_bug_recommendation "$bug")"
            echo ""
        done
}

assess_bug_impact() {
    local bug="$1"
    
    case "$bug" in
        *"expiré"*) echo "Élevé - Risque d'interruption de service" ;;
        *"SlowDNS"*) echo "Moyen - Impact sur les performances" ;;
        *"SNI"*) echo "Moyen - Possible fuite d'information" ;;
        *"CORS"*) echo "Élevé - Risque de sécurité" ;;
        *) echo "À évaluer" ;;
    esac
}

# ==============================================================================
# MODULE: DASHBOARD EN TEMPS RÉEL
# ==============================================================================

generate_dashboard() {
    log "INFO" "Génération du tableau de bord"
    
    local dashboard_file="${REPORT_DIR}/dashboard.html"
    
    cat > "$dashboard_file" << EOF
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard Sécurité - ${ROOT_DOMAIN}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .bug-list { background: #e8f5e9; border-left: 4px solid #4caf50; }
        .critical { background: #ffebee; border-left: 4px solid #f44336; }
        h2 { color: #333; margin-top: 0; }
        .timestamp { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <h1>🔒 Tableau de Bord Sécurité</h1>
    <div class="timestamp">Généré le: $(date)</div>
    
    <div class="dashboard">
        <div class="card">
            <h2>📊 Vue d'ensemble</h2>
            <canvas id="overviewChart"></canvas>
        </div>
        
        <div class="card bug-list">
            <h2>🐛 Bugs Identifiés (Vert = Détecté)</h2>
            <ul>
$(generate_dashboard_bugs)
            </ul>
        </div>
        
        <div class="card">
            <h2>⏱️ Performances DNS</h2>
            <canvas id="dnsChart"></canvas>
        </div>
        
        <div class="card critical">
            <h2>🚨 Problèmes Critiques</h2>
            <ul>
$(generate_critical_issues)
            </ul>
        </div>
    </div>
    
    <script>
        // Chart.js configuration
        const overviewCtx = document.getElementById('overviewChart').getContext('2d');
        new Chart(overviewCtx, {
            type: 'doughnut',
            data: {
                labels: ['Sous-domaines', 'Vulnérabilités', 'SlowDNS', 'Bugs'],
                datasets: [{
                    data: [$(count_subdomains), $(count_tls_vulns), $(count_slow_dns), $(count_total_bugs)],
                    backgroundColor: ['#4caf50', '#f44336', '#ff9800', '#2196f3']
                }]
            }
        });
    </script>
</body>
</html>
EOF
    
    log "SUCCESS" "Dashboard généré: $dashboard_file"
}

generate_dashboard_bugs() {
    grep "\[BUG\]" "${LOG_DIR}/sip_execution.log" | \
        sed 's/.*\[BUG\] //' | \
        head -10 | \
        while read -r bug; do
            echo "                <li style=\"color: green;\">✅ ${bug}</li>"
        done
}

# ==============================================================================
# MODULE: UTILITAIRES AVANCÉS
# ==============================================================================

count_subdomains() {
    find "${DATA_DIR}" -name "*subdomains*.txt" -exec cat {} \; 2>/dev/null | \
        sort -u | wc -l
}

count_tls_vulns() {
    find "${DATA_DIR}/tls" -name "*.json" -exec grep -l "CERTIFICAT_EXPIRÉ\|CHAÎNE_INCOMPLÈTE\|CHIFFREMENT_FAIBLE" {} \; 2>/dev/null | wc -l
}

count_slow_dns() {
    [[ -f "${DATA_DIR}/slow_dns.csv" ]] && wc -l < "${DATA_DIR}/slow_dns.csv" || echo "0"
}

count_total_bugs() {
    grep -c "\[BUG\]" "${LOG_DIR}/sip_execution.log" 2>/dev/null || echo "0"
}

# ==============================================================================
# MODULE: SYSTÈME DE PLUGINS
# ==============================================================================

load_plugins() {
    local plugin_dir="./plugins"
    
    if [[ -d "$plugin_dir" ]]; then
        for plugin in "$plugin_dir"/*.sh; do
            [[ -f "$plugin" ]] && source "$plugin"
        done
    fi
}

# ==============================================================================
# MODULE: GESTION DES ERREURS
# ==============================================================================

error_handler() {
    local error_code="$?"
    local command="$BASH_COMMAND"
    
    log "ERROR" "Erreur dans la commande: $command"
    log "ERROR" "Code d'erreur: $error_code"
    
    # Sauvegarde d'urgence
    emergency_save
    
    exit "$error_code"
}

emergency_save() {
    tar -czf "${BASE_OUTPUT_DIR}_emergency_backup_$(date +%s).tar.gz" \
        "$BASE_OUTPUT_DIR" 2>/dev/null
}

# ==============================================================================
# EXÉCUTION PRINCIPALE
# ==============================================================================

main() {
    trap error_handler ERR
    trap 'log "WARNING" "Interruption utilisateur détectée"; exit 1' INT TERM
    
    # Initialisation
    init_system
    
    # Chargement des plugins
    load_plugins
    
    # Pipeline d'analyse complète
    local -a analysis_steps=(
        "discover_all_assets"
        "perform_security_analysis"
        "analyze_websocket_security"
        "setup_proxy_analysis"
    )
    
    for step in "${analysis_steps[@]}"; do
        log "INFO" "Exécution: $step"
        if ! $step; then
            log "ERROR" "Échec de l'étape: $step"
        fi
    done
    
    # Génération des rapports
    generate_comprehensive_report
    generate_dashboard
    
    # Nettoyage
    cleanup
    
    # Résumé final
    show_final_summary
}

cleanup() {
    if [[ -n "$PROXY_PID" ]]; then
        kill "$PROXY_PID" 2>/dev/null
    fi
    
    # Compression des résultats
    tar -czf "${BASE_OUTPUT_DIR}.tar.gz" "$BASE_OUTPUT_DIR" 2>/dev/null
}

show_final_summary() {
    clear
    
    echo -e "${COLOR_BG_BLUE}════════════════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${COLOR_WHITE}                     ANALYSE TERMINÉE                           ${COLOR_RESET}"
    echo -e "${COLOR_BG_BLUE}════════════════════════════════════════════════════════════════${COLOR_RESET}"
    echo ""
    
    echo -e "${COLOR_CYAN}📊 STATISTIQUES FINALES${COLOR_RESET}"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} Sous-domaines découverts: $(count_subdomains)"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} Vulnérabilités SSL/TLS: $(count_tls_vulns)"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} SlowDNS détectés: $(count_slow_dns)"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} Total des bugs: $(count_total_bugs)"
    echo ""
    
    echo -e "${COLOR_CYAN}📁 RÉSULTATS${COLOR_RESET}"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} Répertoire: ${COLOR_WHITE}$BASE_OUTPUT_DIR${COLOR_RESET}"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} Archive: ${COLOR_WHITE}${BASE_OUTPUT_DIR}.tar.gz${COLOR_RESET}"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} Dashboard: ${COLOR_WHITE}${REPORT_DIR}/dashboard.html${COLOR_RESET}"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} Rapport complet: ${COLOR_WHITE}${REPORT_DIR}/comprehensive_report_*.md${COLOR_RESET}"
    echo ""
    
    echo -e "${COLOR_CYAN}🔍 BUGS PRIORITAIRES (en vert dans les logs)${COLOR_RESET}"
    grep "\[BUG\]" "${LOG_DIR}/sip_execution.log" | \
        sed 's/.*\[BUG\] //' | \
        head -5 | \
        while read -r bug; do
            echo -e "  ${COLOR_GREEN}•${COLOR_RESET} $bug"
        done
    
    echo ""
    echo -e "${COLOR_YELLOW}⚠️  IMPORTANT${COLOR_RESET}"
    echo -e "  Ce système est destiné à des tests autorisés uniquement."
    echo -e "  Respectez les lois locales et obtenez les autorisations nécessaires."
    echo ""
    echo -e "${COLOR_BG_BLUE}════════════════════════════════════════════════════════════════${COLOR_RESET}"
}

# ==============================================================================
# LANCEMENT
# ==============================================================================

[[ $# -eq 0 ]] && {
    echo -e "${COLOR_RED}Usage: $0 <domaine_cible>${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Ex: $0 exemple.com${COLOR_RESET}"
    exit 1
}

# Vérification des privilèges
if [[ "$EUID" -eq 0 ]]; then
    echo -e "${COLOR_YELLOW}[!] Exécution avec les privilèges root détectée${COLOR_RESET}"
fi

# Exécution principale
main "$@"
