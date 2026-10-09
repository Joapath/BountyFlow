# BountyFlow — Ideas para la próxima fase de mejoras

Esto es un backlog, no un compromiso. Quedó pendiente para la conversación
de "qué sigue" después de esta ronda de correcciones. Ordenado por impacto
estimado para uso real en bug bounty, no por orden de aparición en el código.

## Alto impacto

- **Progreso en vivo de fases largas.** `run_cmd()` captura todo el stdout/
  stderr al terminar el proceso (`subprocess.run`). En katana (timeout 2h),
  nuclei (timeout 24h) o subfinder con `-all`, no hay ninguna señal de que
  el escaneo sigue vivo hasta que termina la fase. Cambiar a `Popen` +
  lectura línea por línea (de stderr, que es donde la mayoría de estas
  tools mandan su progreso) daría feedback real sin romper el modo
  `stdout_mode` que ya escribe resultados a archivo.
- **Scope management.** No hay lista de in-scope/out-of-scope, ni soporte
  para wildcard exclusions típicas de programas de bug bounty (`*.staging.
  example.com` fuera de scope, por ejemplo). Agregar un archivo de scope
  opcional (`--scope-file`) que filtre `allsubs.txt` antes de resolve sería
  el primer paso para no pegarle a algo fuera de los límites del programa.
- **Headers custom / cookies de sesión.** Varios programas piden un header
  identificatorio (`X-Bug-Bounty: usuario`) en cada request. Hoy no hay
  forma de inyectar headers custom en httpx/katana/nuclei desde `CONFIG`
  sin editar cada `cmd` a mano.
- **Rate limiting real por nuclei run.** El `score_threshold` de intelligence
  decide qué entra a `high_value_targets.txt`, pero no hay un tope duro de
  URLs para nuclei run B. Si `url_map` tiene 50k entradas con score ≥ 5
  (fácil si un solo host compromete el JS de media app), nuclei corre contra
  las 50k igual. Convendría un `nuclei_max_urls` en config con muestreo o
  top-N por host.

## Medio impacto

- **Dedup por host en `final_targets.txt`.** Ahora mismo, si un host tiene
  `js_leak=True`, *todas* sus URLs en `url_map` reciben ese bonus de score,
  lo que puede inundar el top 200 con URLs del mismo host en vez de dar
  variedad de targets. Se podría limitar a N URLs por host en
  `_write_final_targets()` (o agregar un segundo archivo
  `final_targets_by_host.txt` con el mejor target de cada host).
- **Modo resume real.** `--only` ya permite saltar fases, pero no hay un
  modo "retomá desde donde se cortó" que detecte automáticamente qué fases
  ya tienen output válido y arranque desde la siguiente. Útil si se corta
  la conexión a mitad de un escaneo de 6 horas.
- **Reporte HTML/Markdown final.** Hoy el output son ~15 archivos de texto
  sueltos. Un resumen ejecutivo (HTML standalone o Markdown) que linkee a
  `final_targets.txt`, `takeover_findings.txt` y `nuclei_*` facilitaría
  mandarlo a un compañero de equipo o pegarlo en el informe del programa.
- **Reintentos selectivos en recon.** Si `subfinder` falla por timeout de
  API pero `assetfinder` funciona, hoy no hay retry — se sigue con lo que
  haya. Para un pipeline que "se deja corriendo", un retry con backoff en
  los tools de recon (que son los más dependientes de red externa/rate
  limits de terceros) evitaría perder fuentes por un hiccup momentáneo.

## Bajo impacto / pulido

- Separar `bountyflow.py` (ya en ~2300 líneas) en módulos: `config.py`,
  `phases/*.py`, `intelligence.py`. Sigue siendo manejable como un solo
  archivo, pero si se le siguen agregando fases conviene dividirlo antes de
  que se vuelva incómodo de navegar.
- Tests unitarios para las funciones puras que no dependen de red:
  `normalize_url()`, `_score_entry()`, `_build_url_map()`,
  `validate_domain()`. Son fáciles de cubrir y son justamente las que ya
  tuvieron bugs silenciosos (ver `CORRECCIONES.md`).
- Revisar las regex de `grep_keywords` más ruidosas (`dev` matchea
  "device", `file` matchea "profile", `\.do` matchea ".docx") — no rompen
  nada, pero inflan falsos positivos en el scoring.
- Limpiar `unresolved.txt` y otros artefactos de corridas viejas al
  re-ejecutar una fase, en vez de dejarlos pisados o mezclados con la
  corrida actual (mismo patrón que ya se aplicó en `grep`/`gf` en esta
  ronda).

## Dónde seguir cuando retomemos

Mirar primero `Docs/CORRECCIONES.md` para no repetir el mismo análisis —
ahí está el detalle de qué se rompía y cómo se confirmó cada bug. Este
roadmap asume que esas correcciones ya están en `main`.
