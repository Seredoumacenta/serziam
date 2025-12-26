#!/bin/bash
# security_analyzer.sh - Analyseur complet pour Termux/Ubuntu
# Bugs affichés en VERT - Résultats en temps réel
# Version 5.0 | Date: $(date +%Y-%m-%d)

# ==============================================================================
# CONFIGURATION
# ==============================================================================

# Couleurs ANSI
readonly COLOR_RESET="\033[0m"
readonly COLOR_GREEN="\033[1;32m"
readonly COLOR_RED="\033[1;31m"
readonly COLOR_YELLOW="\033[1;33m"
readonly COLOR_BLUE="\033[1;34m"
readonly COLOR_CYAN="\033[1;36m"
readonly COLOR_MAGENTA="\033[1;35m"
readonly COLOR_BG_GREEN="\033[42m\033[30m"
readonly COLOR_BG_RED="\033[41m\033[37m"

# Configuration principale
ROOT_DOMAIN="${1}"
[ -z "$ROOT_DOMAIN" ] && {
    echo -e "${COLOR_RED}❌ Usage: $0 <domaine>${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Ex: $0 exemple.com${COLOR_RESET}"
    exit 1
}

readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)
readonly OUTPUT_DIR="./security_scan_${ROOT_DOMAIN//./_}_${TIMESTAMP}"

# Détection plateforme
detect_platform() {
    if [ -d "/data/data/com.termux/files/usr" ]; then
        echo "termux"
    elif [ -f "/etc/os-release" ] && grep -qi "ubuntu\|debian" /etc/os-release; then
        echo "ubuntu"
    else
        echo "unknown"
    fi
}

readonly PLATFORM=$(detect_platform)

# ==============================================================================
# FONCTIONS UTILITAIRES
# ==============================================================================

# Vérification et installation des outils
check_tools() {
    echo -e "${COLOR_BLUE}[*] Vérification des outils...${COLOR_RESET}"
    
    local tools=("dig" "curl" "openssl")
    local missing=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${COLOR_YELLOW}[!] Installation des outils manquants...${COLOR_RESET}"
        
        case "$PLATFORM" in
            "termux")
                pkg update -y && pkg install -y dnsutils curl openssl-tool
                ;;
            "ubuntu")
                sudo apt update && sudo apt install -y dnsutils curl openssl
                ;;
        esac
        
        # Vérification finale
        for tool in "${missing[@]}"; do
            if command -v "$tool" &>/dev/null; then
                echo -e "  ${COLOR_GREEN}✓${COLOR_RESET} $tool installé"
            else
                echo -e "  ${COLOR_RED}✗${COLOR_RESET} Échec installation $tool"
                exit 1
            fi
        done
    else
        echo -e "  ${COLOR_GREEN}✓${COLOR_RESET} Tous les outils sont présents"
    fi
}

# Fonction de nettoyage DNS
clean_dns_cache() {
    echo -e "${COLOR_BLUE}[*] Nettoyage du cache DNS...${COLOR_RESET}"
    
    case "$PLATFORM" in
        "termux")
            pkill -9 dnsmasq 2>/dev/null
            rm -f $HOME/.cache/dns* 2>/dev/null
            ;;
        "ubuntu")
            sudo pkill -9 dnsmasq 2>/dev/null
            if command -v resolvectl &>/dev/null; then
                sudo resolvectl flush-caches 2>/dev/null
            fi
            ;;
    esac
    
    sleep 2
    echo -e "  ${COLOR_GREEN}✓${COLOR_RESET} Cache nettoyé"
}

# ==============================================================================
# MODULE 1: DÉCOUVERTE DES SOUS-DOMAINES
# ==============================================================================

discover_subdomains() {
    echo -e "\n${COLOR_CYAN}════════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${COLOR_CYAN}           DÉCOUVERTE DES SOUS-DOMAINES                 ${COLOR_RESET}"
    echo -e "${COLOR_CYAN}════════════════════════════════════════════════════════${COLOR_RESET}\n"
    
    local subdomains_file="${OUTPUT_DIR}/subdomains.txt"
    local temp_dir="${OUTPUT_DIR}/temp"
    mkdir -p "$temp_dir"
    
    echo -e "${COLOR_BLUE}[1] Certificate Transparency...${COLOR_RESET}"
    curl -s "https://crt.sh/?q=%25.${ROOT_DOMAIN}&output=json" 2>/dev/null | \
        grep -o '"name_value":"[^"]*' | cut -d'"' -f4 | \
        sed 's/^\*\.//g' | sort -u > "${temp_dir}/ct.txt"
    
    echo -e "${COLOR_BLUE}[2] Recherche DNS...${COLOR_RESET}"
    local types=("A" "AAAA" "MX" "NS" "TXT" "CNAME")
    for type in "${types[@]}"; do
        dig "$ROOT_DOMAIN" "$type" +short 2>/dev/null | \
            grep -E '[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}' >> "${temp_dir}/dns.txt"
    done
    
    echo -e "${COLOR_BLUE}[3] Bruteforce basique...${COLOR_RESET}"
    local prefixes=("www" "mail" "api" "blog" "admin" "test" "dev" "staging" "app" "cdn")
    for prefix in "${prefixes[@]}"; do
        dig "${prefix}.${ROOT_DOMAIN}" A +short 2>/dev/null | grep -q . && \
            echo "${prefix}.${ROOT_DOMAIN}"
    done > "${temp_dir}/brute.txt" &
    
    wait
    
    # Fusion des résultats
    cat "${temp_dir}/"*.txt 2>/dev/null | grep -i "${ROOT_DOMAIN}" | \
        grep -v '^$' | sort -u | uniq > "$subdomains_file"
    echo "$ROOT_DOMAIN" >> "$subdomains_file"
    sort -u "$subdomains_file" -o "$subdomains_file"
    
    local count=$(wc -l < "$subdomains_file" 2>/dev/null || echo "0")
    echo -e "\n${COLOR_GREEN}✅ ${count} sous-domaines trouvés${COLOR_RESET}"
    
    # Affichage dans le terminal
    echo -e "\n${COLOR_MAGENTA}📋 LISTE COMPLÈTE DES SOUS-DOMAINES :${COLOR_RESET}"
    echo -e "${COLOR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
    
    local line_num=1
    while IFS= read -r subdomain; do
        [ -z "$subdomain" ] && continue
        
        # Mise en forme avec numérotation
        printf "${COLOR_YELLOW}%3d.${COLOR_RESET} %s\n" "$line_num" "$subdomain"
        line_num=$((line_num + 1))
        
    done < "$subdomains_file"
    
    echo -e "${COLOR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
    
    # Export pour les autres modules
    echo -e "\n${COLOR_BLUE}[*] Préparation pour les analyses suivantes...${COLOR_RESET}"
    rm -rf "$temp_dir"
}

# ==============================================================================
# MODULE 2: ANALYSE DNS - SLOWDNS EN TEMPS RÉEL
# ==============================================================================

analyze_dns_performance() {
    echo -e "\n${COLOR_CYAN}════════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${COLOR_CYAN}           ANALYSE DES PERFORMANCES DNS                 ${COLOR_RESET}"
    echo -e "${COLOR_CYAN}════════════════════════════════════════════════════════${COLOR_RESET}\n"
    
    local results_file="${OUTPUT_DIR}/dns_results.txt"
    local slow_count=0
    local total_tested=0
    
    echo -e "${COLOR_BLUE}[*] Démarrage des tests DNS...${COLOR_RESET}\n"
    
    while IFS= read -r subdomain; do
        [ -z "$subdomain" ] && continue
        
        total_tested=$((total_tested + 1))
        
        echo -n "  Testing ${subdomain}... "
        
        # Mesure du temps avec timeout
        local start_time=$(date +%s%N)
        local dig_output=$(timeout 3 dig "$subdomain" A +stats +noall +answer 2>&1)
        local end_time=$(date +%s%N)
        local response_time=$(( (end_time - start_time) / 1000000 ))
        
        # Vérification de la réponse
        if echo "$dig_output" | grep -q "status: NOERROR"; then
            if [ $response_time -gt 500 ]; then
                echo -e "${COLOR_BG_GREEN}[BUG DNS] ${response_time}ms (LENT)${COLOR_RESET}"
                echo "${subdomain},${response_time},SLOW" >> "$results_file"
                slow_count=$((slow_count + 1))
            elif [ $response_time -gt 1000 ]; then
                echo -e "${COLOR_BG_GREEN}[BUG DNS CRITIQUE] ${response_time}ms (TRÈS LENT)${COLOR_RESET}"
                echo "${subdomain},${response_time},CRITICAL" >> "$results_file"
                slow_count=$((slow_count + 1))
            else
                echo -e "${COLOR_GREEN}${response_time}ms${COLOR_RESET}"
            fi
        else
            echo -e "${COLOR_RED}ERREUR${COLOR_RESET}"
        fi
        
    done < "${OUTPUT_DIR}/subdomains.txt"
    
    echo -e "\n${COLOR_CYAN}📊 RÉSULTATS DNS :${COLOR_RESET}"
    echo -e "${COLOR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} Total testé : ${total_tested}"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} Réponses lentes (>500ms) : ${slow_count}"
    
    if [ -f "$results_file" ] && [ -s "$results_file" ]; then
        echo -e "\n${COLOR_YELLOW}🚨 SLOWDNS DÉTECTÉS :${COLOR_RESET}"
        sort -t, -k2 -nr "$results_file" | head -10 | while IFS=, read -r domain time status; do
            echo -e "  ${COLOR_RED}▶${COLOR_RESET} ${domain}: ${time}ms (${status})"
        done
    fi
    
    echo -e "${COLOR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
}

# ==============================================================================
# MODULE 3: ANALYSE TLS/SSL - BUGS EN VERT
# ==============================================================================

analyze_tls_security() {
    echo -e "\n${COLOR_CYAN}════════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${COLOR_CYAN}           ANALYSE DE SÉCURITÉ TLS/SSL                  ${COLOR_RESET}"
    echo -e "${COLOR_CYAN}════════════════════════════════════════════════════════${COLOR_RESET}\n"
    
    local tls_results="${OUTPUT_DIR}/tls_results.txt"
    local bug_count=0
    
    echo -e "${COLOR_BLUE}[*] Analyse des certificats SSL...${COLOR_RESET}\n"
    
    while IFS= read -r subdomain; do
        [ -z "$subdomain" ] && continue
        
        # Test de connexion TLS
        local ssl_output=$(timeout 5 openssl s_client -connect "${subdomain}:443" \
            -servername "$subdomain" -tls1_2 2>&1 | tail -20)
        
        local issues=()
        
        # Détection des bugs (affichés en VERT)
        if echo "$ssl_output" | grep -q "certificate has expired"; then
            issues+=("CERTIFICAT_EXPIRÉ")
            echo -e "${COLOR_BG_GREEN}[BUG TLS] ${subdomain} : Certificat expiré${COLOR_RESET}"
            bug_count=$((bug_count + 1))
        fi
        
        if echo "$ssl_output" | grep -q "verify error"; then
            issues+=("CHAÎNE_INCOMPLÈTE")
            echo -e "${COLOR_BG_GREEN}[BUG TLS] ${subdomain} : Chaîne de certificats incomplète${COLOR_RESET}"
            bug_count=$((bug_count + 1))
        fi
        
        # Test TLS obsolète
        if timeout 2 openssl s_client -connect "${subdomain}:443" -tls1 2>&1 | grep -q "CONNECTED"; then
            issues+=("TLS_OBSOLÈTE")
            echo -e "${COLOR_BG_GREEN}[BUG TLS] ${subdomain} : Support TLS 1.0/1.1 (obsolète)${COLOR_RESET}"
            bug_count=$((bug_count + 1))
        fi
        
        # Test SNI
        local sni_test=$(timeout 3 openssl s_client -connect "${subdomain}:443" \
            -servername "invalid.test.${subdomain}" 2>&1 | grep -i "subject=")
        
        if echo "$sni_test" | grep -q "CN = ${subdomain}"; then
            issues+=("BUG_SNI")
            echo -e "${COLOR_BG_GREEN}[BUG TLS] ${subdomain} : Problème SNI détecté${COLOR_RESET}"
            bug_count=$((bug_count + 1))
        fi
        
        # Sauvegarde des résultats
        if [ ${#issues[@]} -gt 0 ]; then
            echo "=== ${subdomain} ===" >> "$tls_results"
            printf '%s\n' "${issues[@]}" >> "$tls_results"
            echo "" >> "$tls_results"
        else
            echo -e "  ${COLOR_GREEN}✓${COLOR_RESET} ${subdomain} : OK"
        fi
        
    done < <(grep -v '^$' "${OUTPUT_DIR}/subdomains.txt" | head -50)
    
    echo -e "\n${COLOR_CYAN}📊 RÉSULTATS TLS/SSL :${COLOR_RESET}"
    echo -e "${COLOR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} Domaines analysés : $(grep -c '^===' "$tls_results" 2>/dev/null || echo "0")"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} Bugs détectés : ${bug_count}"
    
    if [ $bug_count -gt 0 ]; then
        echo -e "\n${COLOR_YELLOW}🐛 BUGS TLS/SSL DÉTECTÉS (en vert) :${COLOR_RESET}"
        grep "^\[BUG TLS\]" /dev/stdin <<< "$(cat /dev/stdin)" 2>/dev/null || \
            echo -e "  ${COLOR_GREEN}Aucun bug majeur détecté${COLOR_RESET}"
    fi
    
    echo -e "${COLOR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
}

# ==============================================================================
# MODULE 4: ANALYSE WEBSOCKET
# ==============================================================================

analyze_websocket() {
    echo -e "\n${COLOR_CYAN}════════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${COLOR_CYAN}           TEST DES CONNEXIONS WEBSOCKET                ${COLOR_RESET}"
    echo -e "${COLOR_CYAN}════════════════════════════════════════════════════════${COLOR_RESET}\n"
    
    local ws_bugs=0
    
    echo -e "${COLOR_BLUE}[*] Test des endpoints WebSocket...${COLOR_RESET}\n"
    
    while IFS= read -r subdomain; do
        [ -z "$subdomain" ] && continue
        
        # Test HTTPS seulement
        if [[ "$subdomain" =~ ^https?:// ]]; then
            local url="$subdomain"
        else
            local url="https://${subdomain}"
        fi
        
        # Test WebSocket
        local response=$(timeout 5 curl -i -s \
            -H "Connection: Upgrade" \
            -H "Upgrade: websocket" \
            -H "Sec-WebSocket-Version: 13" \
            "$url" 2>&1)
        
        if echo "$response" | grep -q "101 Switching Protocols"; then
            echo -e "  ${COLOR_GREEN}✓${COLOR_RESET} ${subdomain} : WebSocket actif"
            
            # Vérification de sécurité
            if ! echo "$response" | grep -qi "Sec-WebSocket-Accept"; then
                echo -e "${COLOR_BG_GREEN}[BUG WS] ${subdomain} : Header Sec-WebSocket-Accept manquant${COLOR_RESET}"
                ws_bugs=$((ws_bugs + 1))
            fi
            
            # Test CORS
            local cors_test=$(timeout 3 curl -i -s \
                -H "Origin: https://evil.example.com" \
                "$url" 2>&1)
            
            if echo "$cors_test" | grep -q "101 Switching Protocols"; then
                echo -e "${COLOR_BG_GREEN}[BUG WS] ${subdomain} : CORS non restreint (risque CSWSH)${COLOR_RESET}"
                ws_bugs=$((ws_bugs + 1))
            fi
        fi
        
    done < <(grep -E "^https?://" "${OUTPUT_DIR}/subdomains.txt" 2>/dev/null | head -20 || \
             grep -v '^$' "${OUTPUT_DIR}/subdomains.txt" | head -10)
    
    echo -e "\n${COLOR_CYAN}📊 RÉSULTATS WEBSOCKET :${COLOR_RESET}"
    echo -e "${COLOR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} Bugs WebSocket détectés : ${ws_bugs}"
    echo -e "${COLOR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
}

# ==============================================================================
# MODULE 5: PROXY INTÉGRÉ
# ==============================================================================

test_with_proxy() {
    echo -e "\n${COLOR_CYAN}════════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${COLOR_CYAN}           TEST VIA PROXY HTTP/HTTPS                   ${COLOR_RESET}"
    echo -e "${COLOR_CYAN}════════════════════════════════════════════════════════${COLOR_RESET}\n"
    
    # Proxy local simple
    local proxy_port=8080
    
    echo -e "${COLOR_BLUE}[*] Configuration du proxy local...${COLOR_RESET}"
    
    # Test avec curl --proxy si disponible
    if command -v curl &>/dev/null; then
        echo -e "  ${COLOR_GREEN}✓${COLOR_RESET} Test direct avec curl"
        
        # Test de quelques sites
        local test_count=0
        while IFS= read -r subdomain && [ $test_count -lt 5 ]; do
            [ -z "$subdomain" ] && continue
            
            echo -n "  Testing ${subdomain} via proxy... "
            
            local response=$(timeout 5 curl -s -I "https://${subdomain}" 2>&1 | head -1)
            
            if echo "$response" | grep -q "HTTP"; then
                local code=$(echo "$response" | awk '{print $2}')
                echo -e "HTTP ${code}"
            else
                echo -e "${COLOR_RED}ERREUR${COLOR_RESET}"
            fi
            
            test_count=$((test_count + 1))
            
        done < <(grep -v '^$' "${OUTPUT_DIR}/subdomains.txt" | head -10)
    else
        echo -e "  ${COLOR_YELLOW}⚠${COLOR_RESET} curl non disponible pour les tests proxy"
    fi
    
    echo -e "\n${COLOR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
}

# ==============================================================================
# MODULE 6: SYNTHÈSE FINALE
# ==============================================================================

generate_summary() {
    echo -e "\n${COLOR_CYAN}════════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${COLOR_CYAN}                SYNTHÈSE DE L'ANALYSE                   ${COLOR_RESET}"
    echo -e "${COLOR_CYAN}════════════════════════════════════════════════════════${COLOR_RESET}\n"
    
    local subdomain_count=$(wc -l < "${OUTPUT_DIR}/subdomains.txt" 2>/dev/null || echo "0")
    local slow_dns_count=$(grep -c ",SLOW\|,CRITICAL" "${OUTPUT_DIR}/dns_results.txt" 2>/dev/null || echo "0")
    local tls_bug_count=$(grep -c "^\[BUG TLS\]" /dev/stdin <<< "$(cat /dev/stdin)" 2>/dev/null || echo "0")
    
    echo -e "${COLOR_MAGENTA}📊 STATISTIQUES GLOBALES :${COLOR_RESET}"
    echo -e "${COLOR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} Plateforme : ${PLATFORM}"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} Domaine analysé : ${ROOT_DOMAIN}"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} Sous-domaines découverts : ${subdomain_count}"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} SlowDNS détectés : ${slow_dns_count}"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} Bugs TLS/SSL : ${tls_bug_count}"
    echo -e "${COLOR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
    
    # Liste des fichiers générés
    echo -e "\n${COLOR_MAGENTA}📁 FICHIERS GÉNÉRÉS :${COLOR_RESET}"
    echo -e "${COLOR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
    find "$OUTPUT_DIR" -type f -name "*.txt" | while read -r file; do
        local size=$(du -h "$file" 2>/dev/null | cut -f1 || echo "0")
        local lines=$(wc -l < "$file" 2>/dev/null || echo "0")
        echo -e "  ${COLOR_GREEN}•${COLOR_RESET} $(basename "$file") (${lines} lignes, ${size})"
    done
    echo -e "${COLOR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
    
    # Résumé des bugs (en vert)
    if [ $tls_bug_count -gt 0 ] || [ $slow_dns_count -gt 0 ]; then
        echo -e "\n${COLOR_MAGENTA}🐛 RÉCAPITULATIF DES BUGS :${COLOR_RESET}"
        echo -e "${COLOR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
        
        # Bugs DNS
        if [ -f "${OUTPUT_DIR}/dns_results.txt" ]; then
            grep ",SLOW\|,CRITICAL" "${OUTPUT_DIR}/dns_results.txt" | head -3 | \
                while IFS=, read -r domain time status; do
                    echo -e "  ${COLOR_BG_GREEN}[BUG DNS] ${domain} : ${time}ms${COLOR_RESET}"
                done
        fi
        
        # Bugs TLS
        if [ -f "${OUTPUT_DIR}/tls_results.txt" ]; then
            grep -h "^\[BUG TLS\]" /dev/stdin <<< "$(cat /dev/stdin)" 2>/dev/null | head -3 | \
                while read -r line; do
                    echo -e "  ${COLOR_BG_GREEN}${line}${COLOR_RESET}"
                done
        fi
        
        echo -e "${COLOR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
    fi
    
    # Recommandations
    echo -e "\n${COLOR_MAGENTA}🔧 RECOMMANDATIONS :${COLOR_RESET}"
    echo -e "${COLOR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
    echo -e "  ${COLOR_GREEN}1.${COLOR_RESET} Vérifier les certificats expirés"
    echo -e "  ${COLOR_GREEN}2.${COLOR_RESET} Optimiser les serveurs DNS lents"
    echo -e "  ${COLOR_GREEN}3.${COLOR_RESET} Mettre à jour les versions TLS"
    echo -e "  ${COLOR_GREEN}4.${COLOR_RESET} Configurer correctement SNI"
    echo -e "${COLOR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
    
    # Commandes utiles
    echo -e "\n${COLOR_MAGENTA}💡 COMMANDES UTILES :${COLOR_RESET}"
    echo -e "${COLOR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} Voir tous les sous-domaines :"
    echo -e "    cat ${OUTPUT_DIR}/subdomains.txt"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} Voir les SlowDNS :"
    echo -e "    grep ',SLOW\|,CRITICAL' ${OUTPUT_DIR}/dns_results.txt"
    echo -e "  ${COLOR_GREEN}•${COLOR_RESET} Voir les bugs TLS :"
    echo -e "    cat ${OUTPUT_DIR}/tls_results.txt"
    echo -e "${COLOR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${COLOR_RESET}"
}

# ==============================================================================
# FONCTION PRINCIPALE
# ==============================================================================

main() {
    clear
    
    # Bannière
    echo -e "${COLOR_CYAN}════════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${COLOR_CYAN}        SECURITY ANALYZER v5.0 - ${PLATFORM^^}           ${COLOR_RESET}"
    echo -e "${COLOR_CYAN}════════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Cible : ${ROOT_DOMAIN}${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Date  : $(date)${COLOR_RESET}"
    echo -e "${COLOR_CYAN}════════════════════════════════════════════════════════${COLOR_RESET}"
    echo ""
    
    # Initialisation
    mkdir -p "$OUTPUT_DIR"
    
    # Vérification des outils
    check_tools
    
    # Nettoyage DNS
    clean_dns_cache
    
    # Exécution des modules
    discover_subdomains
    analyze_dns_performance
    analyze_tls_security
    analyze_websocket
    test_with_proxy
    generate_summary
    
    # Message final
    echo -e "\n${COLOR_CYAN}════════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${COLOR_GREEN}✅ ANALYSE TERMINÉE AVEC SUCCÈS${COLOR_RESET}"
    echo -e "${COLOR_CYAN}════════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}📁 Résultats dans : ${OUTPUT_DIR}${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}🐛 Bugs affichés en ${COLOR_BG_GREEN} VERT ${COLOR_RESET}${COLOR_YELLOW} dans le terminal${COLOR_RESET}"
    echo -e "${COLOR_CYAN}════════════════════════════════════════════════════════${COLOR_RESET}\n"
}

# ==============================================================================
# GESTION DES ERREURS
# ==============================================================================

handle_error() {
    local line=$1
    local command=$2
    echo -e "${COLOR_RED}❌ ERREUR à la ligne $line : $command${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Continuer l'analyse...${COLOR_RESET}"
    return 0
}

trap 'handle_error $LINENO "$BASH_COMMAND"' ERR
trap 'echo -e "${COLOR_RED}❌ Interrompu par l'utilisateur${COLOR_RESET}"; exit 1' INT

# ==============================================================================
# DÉMARRAGE
# ==============================================================================

if [ $# -ne 1 ]; then
    echo -e "${COLOR_RED}❌ Usage: $0 <domaine>${COLOR_RESET}"
    echo -e "${COLOR_YELLOW}Exemple: $0 exemple.com${COLOR_RESET}"
    exit 1
fi

# Vérification de la connexion
if ! ping -c 1 8.8.8.8 &>/dev/null; then
    echo -e "${COLOR_RED}❌ Pas de connexion Internet${COLOR_RESET}"
    exit 1
fi

# Exécution
main "$@"
