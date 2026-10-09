# BountyFlow — Correcciones aplicadas (2026-10-08)

Este documento registra qué estaba roto, cómo se confirmó (no por lectura de
código solamente — se probó contra las herramientas reales instaladas en el
Kali donde corre BountyFlow) y qué se cambió. Todo lo de abajo ya está
aplicado en `bountyflow.py`.

---

## 1. Grep de keywords devolvía fragmentos de URL, no URLs completas (CRÍTICO)

**Dónde:** `phase_grep` → `_grep_one()`

**Qué pasaba:** el comando era
```
grep -iEo "^.*{pattern}.*$" cleanurls.txt
```
Con patrones de una sola palabra (`admin`) funcionaba. Pero la mayoría de los
patrones son alternancias (`login|signin|sign-in|log-in`), y en POSIX ERE el
operador `|` tiene **menor precedencia** que la concatenación: el patrón se
interpreta como `(^.*login)|(signin)|(sign-in)|(log-in.*$)`, no como
`^.*(login|signin|sign-in|log-in).*$`. Con `-o` (solo imprimir el match),
grep devolvía el fragmento que matcheaba cada rama, no la línea completa.

**Confirmado así** (`cleanurls.txt` con 4 URLs de login variadas):
```
$ grep -iEo '^.*login|signin|sign-in|log-in.*$' cleanurls.txt
signin
https://a.com/login
log-in/foo?z=2
```
Ninguna de esas tres líneas es una URL completa. El resultado se escribía en
`08_grep/login.txt`, y después `_load_grep_annotations()` le aplicaba
`normalize_url()` a esos fragmentos — que nunca coinciden con ninguna
entrada real de `url_map`, así que el scoring de grep quedaba **anulado en
silencio** para cualquier keyword con alternancia (casi todas).

**Fix:** sacar `-o` y el anclaje `^...$`, dejar que grep devuelva la línea
completa cuando matchea en cualquier parte:
```python
cmd = ["grep", "-iE", "-e", pattern, str(self.files["cleanurls"])]
```
Verificado con el mismo archivo de prueba: ahora devuelve las dos URLs de
login completas, tal cual.

---

## 2. jsleak fallaba siempre — flag inexistente (CRÍTICO)

**Dónde:** `CONFIG["jsleak"]["cmd"]`

**Qué pasaba:** el comando era
```
jsleak -s -v -k -l {input}
```
`jsleak` no tiene flag `-v`. Confirmado ejecutándolo tal cual:
```
$ jsleak -s -v -k -l archivo.txt
flag provided but not defined: -v
Usage of jsleak: ...
```
Go's `flag` package corta la ejecución ante un flag no reconocido e imprime
el usage — exit code 0 (no truthy) pero **cero trabajo real**. Como además
`run_cmd()` solo marca fallo si `returncode != 0` y el archivo de salida
está vacío, esto pasaba desapercibido: la fase "corría", pero
`jsleak_results.txt` quedaba vacío siempre, en cada corrida que se haya
hecho con esta tool.

Encima, `{input}` se pasaba como argumento posicional. jsleak no lee un
archivo por argumento — **lee URLs por stdin**. Confirmado:
```
$ jsleak -s -v -k -l archivo.txt     # con -v: error de flag, no llega a leer nada
$ cat archivo.txt | jsleak -s -k -l  # correcto: sí procesa
[+] Found link: ...
```

**Fix:**
- Se quitó `-v` del comando.
- `run_cmd()` ganó un parámetro nuevo `stdin_file`: si se pasa, abre ese
  archivo y lo conecta al stdin del subproceso.
- `phase_jsleak()` ahora llama `run_cmd(..., stdin_file=self.files["js_urls"])`
  en vez de intentar pasar el archivo como argumento.

Validado con una URL real (`code.jquery.com/jquery-3.6.0.min.js`) por stdin:
jsleak corrió y devolvió hallazgos reales.

---

## 3. `url_map` guardaba la URL normalizada (con params vaciados), no la real (CRÍTICO)

**Dónde:** `_build_url_map()`

**Qué pasaba:**
```python
source = (self.files["urls_norm"] if self.files["urls_norm"].exists()
          else self.files["cleanurls"])
```
`urls_normalized.txt` contiene **solo las formas normalizadas**
(`/api/user?id=&page=`), generadas por `_normalize_urls()` para deduplicar
vistas de URL con distintos valores de parámetro. Ese archivo nunca guardó
el mapeo de vuelta a una URL real — y como casi siempre existe (se genera en
cada corrida de `crawl`), `_build_url_map()` lo preferiría *siempre* sobre
`cleanurls.txt`.

Resultado: cada entrada de `url_map` tenía `"url"` = la versión con
parámetros vacíos. Esa misma URL rota es la que se escribe en
`high_value_targets.txt` y `final_targets.txt` — es decir, **nuclei
terminaba escaneando URLs con `?id=&token=` en vez de valores reales**, y
cualquiera que abriera `final_targets.txt` para explotar algo manualmente
se encontraba con un endpoint no navegable.

**Confirmado** armando un `cleanurls.txt` sintético con params reales y
corriendo `phase_intelligence()` aislada:
```
normalized: https://a.example.com/api/v1/users?id=&token=
  url guardada (ANTES del fix): https://a.example.com/api/v1/users?id=&token=
  url guardada (DESPUÉS del fix): https://a.example.com/api/v1/users?id=5&token=abc123
```

**Fix:** `_build_url_map()` ahora lee siempre de `cleanurls.txt` (URLs
reales). `urls_normalized.txt` sigue generándose y queda como artefacto
informativo (para ver cuántas "formas" de URL únicas hay), pero deja de ser
la fuente de verdad para el pipeline de intelligence/scoring/nuclei.

---

## 4. Takeover: los candidatos a CNAME colgante se buscaban en el conjunto equivocado

**Dónde:** `phase_dns()`

**Qué pasaba:** `cname_hosts.txt` (la lista que alimenta subzy en la fase de
takeover) se construía a partir de `live.txt` — es decir, solo subdominios
que **ya respondieron HTTP**. Pero el escenario clásico de subdomain
takeover es justo el opuesto: un CNAME que apunta a un servicio externo
(S3, Heroku, Azure, etc.) que ya no existe, y por lo tanto **no resuelve
por A ni responde HTTP**. Esos hosts se filtran en la fase `resolve` y
nunca llegan a `live.txt` — con el código viejo, jamás se los tomaba como
candidatos a takeover. La fase que más valor aporta en bug bounty
(takeover) estaba mirando el universo que menos probabilidad tiene de
contener hallazgos.

**Fix:** `phase_dns()` ahora resuelve A/CNAME sobre `allsubs.txt` completo
(todos los subdominios enumerados en fase 1), no solo sobre `live.txt`.
dnsx es liviano comparado con httpx/katana, así que el costo adicional es
bajo. `dns_records.txt`/`cname_hosts.txt` ahora cubren todo el universo de
subdominios, con o sin resolución HTTP.

---

## 5. Resolución DNS "externa" podía no ser realmente externa

**Dónde:** `CONFIG["dnsx_resolve"]`, `CONFIG["dnsx"]`

**Qué pasaba:** la fase `resolve` (pensada específicamente para filtrar
subdominios internos cuando se corre detrás de VPN) usaba `dnsx -a` sin
especificar resolvers. Sin `-r`, dnsx usa los resolvers del sistema — si la
VPN empuja su propio DNS (algo común en VPNs corporativas/de assessment),
un host interno puede resolver igual, y el filtro completo pierde sentido
silenciosamente.

**Fix:** se agregó `-r 1.1.1.1,8.8.8.8,9.9.9.9` (resolvers públicos,
confirmado que `dnsx` soporta `-r`/`-resolver` en la versión instalada) a
`dnsx_resolve` y a `dnsx` (fase 4). Ahora "resuelve desde afuera" significa
lo que dice.

---

## 6. Templates de nuclei: rutas obsoletas + tech-detect nunca mostraba nada

**Dónde:** `CONFIG["nuclei"]`

**Qué pasaba:**
```python
"host_templates": ["takeovers/", "misconfiguration/", "default-logins/",
                    "dns/", "network/", "technologies/"],
"url_templates":  ["cves/", "vulnerabilities/", "exposures/"],
"cmd": [..., "-severity", "low,medium,high,critical", ...]
```
Verificado contra `~/nuclei-templates` real (layout v9+, que es el que trae
tu Kali actualizado): `cves`, `default-logins`, `exposures`,
`misconfiguration`, `takeovers`, `technologies` y `vulnerabilities` viven
bajo `http/`, no en la raíz. `dns/` y `network/` sí son carpetas raíz.
Pasarle `-t takeovers/` a nuclei cuando la carpeta real es
`http/takeovers/` no matchea nada — la fase "corría" pero procesaba muchas
menos plantillas de las que el usuario pensaba (o ninguna, según cómo
resuelva nuclei la ruta relativa).

Además, `technologies/` son templates de severidad **info** (fingerprinting
puro, sin vulnerabilidad). Con `-severity low,medium,high,critical` ese
template nunca iba a producir una sola línea de output — estaba en la lista
pero era dead weight.

**Fix:**
```python
"host_templates": ["http/takeovers/", "http/misconfiguration/",
                    "http/default-logins/", "dns/", "network/",
                    "http/technologies/"],
"url_templates":  ["http/cves/", "http/vulnerabilities/", "http/exposures/"],
"cmd": [..., "-severity", "info,low,medium,high,critical", ...]
```
Se agregó `info` a la severidad a propósito (es la única forma de que
`technologies/` sirva para algo: dar contexto de stack en el reporte).

---

## 7. Fases con `--focus` distinto dejaban basura de la corrida anterior

**Dónde:** `phase_grep()`, `phase_gf()`

**Qué pasaba:** si corrías una vez con `--focus secrets` y después otra con
`--focus sqli`, los archivos `08_grep/*.txt` y `09_gf/gf_*.txt` de
categorías que ya no están activas en el segundo `--focus` seguían ahí
desde la corrida anterior. `phase_intelligence()` lee **todo** lo que
encuentra en esas carpetas (`glob("*.txt")`), sin importar si corresponde a
la corrida actual — así que el scoring se contaminaba con categorías de un
focus que el usuario ya había dejado atrás.

**Fix:** ambas fases borran su carpeta de salida (`08_grep/*.txt`,
`09_gf/gf_*.txt`) al arrancar, antes de escribir los resultados de la
corrida actual.

---

## 8. Errores de tipeo en `--skip`/`--only` se ignoraban en silencio

**Qué pasaba:** `python3 bountyflow.py -d x.com --only jsregx` (typo) no
corría ninguna fase y no avisaba nada — `should_run()` simplemente nunca
encontraba `"jsregx"` en la lista de fases reales.

**Fix:** se agregó `VALID_PHASES` y una validación en `main()` que avisa
(sin bloquear la ejecución, por si el usuario agrega una fase custom más
adelante) cuando una fase en `--skip`/`--only` no es reconocida.

---

## 9. Ctrl+C dejaba traceback crudo y el log sin cerrar

**Fix:** `main()` ahora envuelve `flow.run()` en try/except. `KeyboardInterrupt`
se maneja con un mensaje prolijo, intenta imprimir el resumen parcial, cierra
el logger, y sale con código 130 (convención estándar para SIGINT). Cualquier
otra excepción no prevista se loguea igual antes de volver a lanzarse (no se
traga el traceback, pero el log queda cerrado y con contexto).

---

## 10. Rebranding: restos de "PentestFlow" (nombre viejo del proyecto)

La clase principal era `class PentestFlow`, el User-Agent de las fetches de
`.js` decía `"Mozilla/5.0 (PentestFlow; +recon)"`, el header de
`final_targets.txt` decía "PENTESTFLOW v3", y el banner ASCII art no
representaba ninguna de las dos palabras con claridad. Todo esto se
renombró a BountyFlow (clase `BountyFlow`, User-Agent, header de
`final_targets.txt`, banner simplificado y legible). `requirements.txt` y
el README también mencionaban `pentestflow.py`/"PentestFlow" en comentarios;
se corrigieron.

Además:
- `requirements.txt` ya no se ve como un requirements de pip (llevaba
  comentarios diciendo "esto no es instalable con pip" pero el propio
  nombre del archivo invita al error); se dejó más explícito arriba de
  todo y se corrigió la mención de `uro` (es paquete de Python/pip, no un
  módulo Go — estaba mal catalogado en el README bajo "Go tools").
- `.gitignore` solo ignoraba `Backups/`; se agregó `output/` (resultados de
  escaneos reales — nunca deberían subirse a un repo), `*.log`,
  `__pycache__/`, `*.pyc`.
- El default de `crtsh.enabled` pasó de `True` a `False`: con la ruta
  placeholder (`/ruta/completa/a/crtsh.py`) sin editar, cada corrida tiraba
  un warning de "script no encontrado" para una tool que el usuario todavía
  no configuró. Ahora queda explícitamente opt-in.

---

## Qué se probó y qué no

Se verificó cada fix contra los binarios reales instalados en este Kali
(`httpx 1.3.1`, `dnsx`, `nuclei v1.7.0`, `jsleak`, `gf`, `katana v1.7.0`,
`subfinder`), con datos sintéticos cuando no había necesidad de red real
(grep, normalización de URLs, scoring, `url_map`) y con una petición de red
real cuando hacía falta confirmar comportamiento de la tool (httpx contra
`example.com`, dnsx resolviendo `example.com`, jsleak contra un `.js` real
de `code.jquery.com`).

**No se probó** una corrida end-to-end completa del pipeline de 13 fases
contra un dominio real (no es el objetivo de esta sesión, y herramientas
como `gau`, `subzy`, `socialhunter` y `findomain` no están instaladas en
este entorno — el código las omite de forma defensiva vía `check_tool()`,
pero no se pudo confirmar su integración real). Antes de un uso serio en un
programa de bug bounty, recomiendo correr una vez contra un dominio de
scope reducido y revisar `logs/run_*.log` fase por fase.
