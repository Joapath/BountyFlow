# BountyFlow 🔍 v3

Herramienta de reconocimiento y pentest automatizado para bug bounty. Orquesta múltiples herramientas en el orden correcto, filtra resolución DNS externa antes de pegarle a nada, corre todo en modo VPN-safe, y organiza los resultados por fase con un motor de scoring propio al final.

---

## Flujo de trabajo

```
FASE 1: RECONOCIMIENTO
  subfinder + assetfinder + sublist3r + shodanx + findomain + crtsh
        ↓
  allsubs.txt  (sort -u, deduplicado)

FASE 2: RESOLVE (filtro de resolución externa)
  allsubs.txt → dnsx -a          → resolved.txt (resuelven desde afuera)
                                  → unresolved.txt (posibles internos)

FASE 3: HTTPX
  resolved.txt → httpx -fr       → live.txt
  resolved.txt → httpx (tech)    → live_tech.json

FASE 4: DNS
  live.txt    → dnsx -a -cname -json → dns_records.json / .txt
                                      → cname_hosts.txt

FASE 5: TAKEOVER
  cname_hosts.txt → subzy        → takeover_findings.txt

FASE 6: OSINT
  live.txt    → socialhunter     → socialhunter.txt

FASE 7: CRAWLING
  live.txt    → katana ┐
  dominio     → gau     ├→ urls.txt (merge) → uro → cleanurls.txt
  dominio     → waybackurls ┘

FASE 8: GREP KEYWORDS
  cleanurls.txt → grep (admin, login, auth, api, ...) → grep/admin.txt, etc.

FASE 9: GF PATTERNS
  cleanurls.txt → gf xss/sqli/ssrf/... → gf/gf_xss.txt, etc.

FASE 10: JSLEAK
  cleanurls.txt → jsleak -s -v -k → jsleak_results.txt

FASE 11: JS REGEX (propio)
  .js files → regex (endpoints, api keys, aws keys, jwt, subdominios)
            → jsregex/*.txt + secrets_hosts.txt

FASE 12: INTELLIGENCE
  live_tech.json + gf/* + grep/* + jsleak + jsregex
        ↓ correlación por URL normalizada + scoring
  url_map.json / final_targets.txt / high_value_targets.txt

FASE 13: NUCLEI ← (el más pesado, va al final)
  live.txt            → nuclei (takeovers/, misconfig/, ...) → findings_hosts.txt
  high_value_targets  → nuclei (cves/, vulnerabilities/...)  → findings_urls.txt
```

---

## Modo VPN-safe

Pensada para correr tranquilo sin que se cuelgue el escaneo por estar detrás de VPN:

- **Fase resolve**: filtra subdominios que no resuelven desde afuera (típicos internos mezclados entre fuentes) antes de que lleguen a httpx/katana/nuclei, que es donde se cuelgan los escaneos por DNS roto.
- **Stagger**: las fases con tools en paralelo (`recon`, `crawl`) no los lanza todos de una — espera `CONFIG["vpn_safe"]["stagger_delay"]` segundos entre cada lanzamiento.
- **Paralelismo bajo**: `CONFIG["vpn_safe"]["max_parallel_tools"]` limita cuántos tools de red corren en simultáneo (default: 2).
- **Threads/concurrencia conservadores** en httpx, dnsx, katana y nuclei (ya vienen bajados en el `CONFIG` por defecto).

```python
"vpn_safe": {
    "max_parallel_tools": 2,   # tools de red corriendo en simultáneo
    "stagger_delay": 2.0,      # segundos entre el lanzamiento de cada uno
},
```

---

## Instalación de dependencias

```bash
# Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/s0md3v/uro@latest
go install -v github.com/tomnomnom/gf@latest
go install -v github.com/channyein1337/jsleak@latest
go install -v github.com/LukaSikic/subzy@latest

# Python tools
pip install sublist3r

# findomain
wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux -O /usr/local/bin/findomain
chmod +x /usr/local/bin/findomain

# shodanx
pip install shodanx
# o: go install github.com/RevoltSecurities/ShodanX@latest

# socialhunter
go install github.com/utkusen/socialhunter@latest

# gf patterns (carpeta ~/.gf)
git clone https://github.com/tomnomnom/gf
cp gf/examples/*.json ~/.gf/
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf-extra
cp ~/.gf-extra/*.json ~/.gf/

# Nuclei templates
nuclei -update-templates
```

### crtsh.py (script propio)

No es un binario de PATH, es un script propio en Python que vos ya tenés. Hay que
configurarlo a mano en `CONFIG["recon_tools"]["crtsh"]`:

```python
"crtsh": {
    "enabled": True,
    "script_path": "/ruta/completa/a/crtsh.py",   # ← editar
    "output_glob": "*{domain}*",                   # ← patrón del archivo que genera
},
```

El script corre con `cwd` en su propia carpeta (porque ahí tira su output en vez de
respetar `-o`) y PentestFlow busca el archivo más reciente que matchee `output_glob`
para copiarlo al pipeline. Si no está configurado, se omite solo sin romper nada más.

---

## Uso

```bash
# Escaneo completo
python3 bountyflow.py -d example.com

# Cambiar directorio de salida
python3 bountyflow.py -d example.com --output ~/pentests

# Omitir fases pesadas
python3 bountyflow.py -d example.com --skip nuclei,jsleak

# Ejecutar solo reconocimiento + filtro de resolución + httpx
python3 bountyflow.py -d example.com --only recon,resolve,httpx

# Focus mode: boostea scoring según el tipo de bug que buscás
python3 bountyflow.py -d example.com --focus api,auth

# Verificar herramientas instaladas
python3 bountyflow.py --check
```

### Re-escaneo incremental

Al final de cada corrida se guarda un snapshot y se compara contra el anterior,
generando `new_subdomains.txt` y `new_urls.txt` en `diff/`. Para procesar solo lo
nuevo sin repetir todo el pipeline:

```bash
python3 bountyflow.py -d example.com \
  --only resolve,httpx,dns,takeover,crawl,grep,gf,jsleak,jsregex,intelligence,nuclei
```

---

## Estructura de output

```
output/
└── example_com/
    ├── 01_recon/
    │   ├── subfinder.txt
    │   ├── assetfinder.txt
    │   ├── sublist3r.txt
    │   ├── shodanx.txt
    │   ├── findomain.txt
    │   ├── crtsh.txt
    │   └── allsubs.txt           ← todos combinados, sort -u
    ├── 02_resolve/
    │   ├── resolved.txt          ← subdominios que resuelven desde afuera
    │   └── unresolved.txt        ← posibles internos / no resueltos
    ├── 03_httpx/
    │   ├── live.txt              ← hosts vivos (httpx -fr)
    │   └── live_tech.json        ← tech, IPs, títulos, ASN
    ├── 04_dns/
    │   ├── dns_records.json
    │   ├── dns_records.txt
    │   └── cname_hosts.txt       ← candidatos a takeover
    ├── 05_takeover/
    │   └── takeover_findings.txt
    ├── 06_social/
    │   └── socialhunter.txt
    ├── 07_crawl/
    │   ├── katana_raw.txt
    │   ├── gau_raw.txt
    │   ├── wayback_raw.txt
    │   ├── urls.txt              ← merge de los tres crawlers
    │   ├── cleanurls.txt         ← deduplicadas con uro
    │   └── urls_normalized.txt   ← params vaciados
    ├── 08_grep/
    │   ├── admin.txt
    │   ├── login.txt
    │   ├── api.txt
    │   └── ...
    ├── 09_gf/
    │   ├── gf_xss.txt
    │   ├── gf_sqli.txt
    │   └── ...
    ├── 10_jsleak/
    │   ├── js_urls.txt
    │   └── jsleak_results.txt
    ├── 11_jsregex/
    │   ├── endpoints_abs.txt
    │   ├── api_keys.txt
    │   ├── jwt.txt
    │   ├── subdomains.txt
    │   └── secrets_hosts.txt     ← hosts con posibles secretos
    ├── 12_intelligence/
    │   ├── url_map.json
    │   ├── final_targets.txt     ⭐ top targets con scoring
    │   └── high_value_targets.txt
    ├── 13_nuclei/
    │   ├── findings_hosts.txt
    │   └── findings_urls.txt
    ├── diff/
    │   ├── new_subdomains.txt
    │   ├── gone_subdomains.txt
    │   └── new_urls.txt
    ├── _history/                 ← snapshots para el diff incremental
    └── logs/
        └── run_20240101_120000.log
```

---

## Personalización

Toda la configuración está en el diccionario `CONFIG` al inicio del script.

### Añadir un template a nuclei
```python
"nuclei": {
    "url_templates": [
        "cves/",
        "vulnerabilities/",
        "mi-template-custom/",  # ← añadir aquí
    ],
```

### Añadir un patrón gf
```python
"gf_patterns": [
    "xss", "sqli",
    "mi-patron-custom",  # ← añadir aquí
],
```

### Añadir una keyword de grep
```python
"grep_keywords": {
    "kubernetes": r"kubernetes|kubectl|k8s",  # ← añadir aquí
},
```

### Añadir un regex propio de jsregex
```python
# dentro de _build_js_patterns()
"gcp_keys": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),  # ← añadir aquí
```

### Deshabilitar una herramienta de recon
```python
"recon_tools": {
    "shodanx": {
        "enabled": False,  # ← cambiar a False
    },
```

### Cambiar flags de katana (más profundidad)
```python
"katana": {
    "cmd": [
        "katana", "-list", "{input}", "-o", "{output}",
        "-d", "10",   # ← aumentar profundidad
        ...
    ],
```

### Ajustar el modo VPN-safe
```python
"vpn_safe": {
    "max_parallel_tools": 4,   # ← subir si tu conexión aguanta más
    "stagger_delay": 1.0,      # ← bajar para arrancar más rápido
},
```

### Ajustar pesos de scoring
```python
"scoring": {
    "js_regex_secret_host": 5,  # ← subir si querés priorizar secrets por sobre gf/grep
},
```

---

## Fases disponibles

| Fase | Herramientas | Input | Output |
|------|-------------|-------|--------|
| `recon` | subfinder, assetfinder, sublist3r, shodanx, findomain, crtsh | dominio | allsubs.txt |
| `resolve` | dnsx | allsubs.txt | resolved.txt, unresolved.txt |
| `httpx` | httpx | resolved.txt (o allsubs.txt) | live.txt, live_tech.json |
| `dns` | dnsx | live.txt | dns_records.json/.txt, cname_hosts.txt |
| `takeover` | subzy | cname_hosts.txt | takeover_findings.txt |
| `social` | socialhunter | live.txt | socialhunter.txt |
| `crawl` | katana, gau, waybackurls, uro | live.txt / dominio | urls.txt, cleanurls.txt, urls_normalized.txt |
| `grep` | grep | cleanurls.txt | grep/*.txt |
| `gf` | gf | cleanurls.txt | gf/*.txt |
| `jsleak` | jsleak | cleanurls.txt | jsleak_results.txt |
| `jsregex` | regex propio | cleanurls.txt (.js) | jsregex/*.txt, secrets_hosts.txt |
| `intelligence` | — (correlación propia) | live_tech + gf + grep + jsleak + jsregex | url_map.json, final_targets.txt, high_value_targets.txt |
| `nuclei` | nuclei | live.txt, high_value_targets.txt | findings_hosts.txt, findings_urls.txt |
