# BountyFlow — Features nuevas (más allá de corrección de bugs)

A diferencia de `CORRECCIONES.md` (bugs que ya existían y se arreglaron),
esto documenta funcionalidad nueva agregada a pedido.

---

## `-dL` / `--domain-list` — lista de dominios, al estilo subfinder (2026-10-08)

**Pedido del usuario:** poder pasar una lista de dominios (como el `-dL` de
subfinder) y que se procesen uno después del otro, sin saturar la VPN, pero
sin que el batch completo se vuelva innecesariamente lento.

### Decisión de diseño

Secuencial **entre dominios**, en paralelo **dentro** de cada dominio —
exactamente el mismo modelo que ya usaba `vpn_safe` para las tools de una
misma fase. No se agregó ningún paralelismo nuevo entre dominios porque
sería contradictorio con el pedido (correr 2 dominios en simultáneo = 2x
las conexiones activas contra la misma VPN).

La velocidad no se resiente tanto como "procesar N dominios en serie"
suena a primera vista: cada dominio igual corre sus fases con el
paralelismo interno normal (`max_parallel_tools`, stagger, etc.), así que
el único costo extra del modo batch es la pausa fija entre dominios
(`between_domains_delay`, default 5s — configurable con `--domain-delay` o
en `CONFIG["vpn_safe"]`). Para una lista de 20 dominios eso son 100
segundos de pausa total sobre un escaneo que de por sí tarda horas por
dominio — insignificante.

### Qué se agregó

- **`CONFIG["vpn_safe"]["between_domains_delay"]`** (default `5.0`): pausa
  entre el final de un dominio y el arranque del siguiente. Es solo un
  respiro de red, no afecta el paralelismo interno de cada dominio.
- **`read_domain_list(path)`**: helper a nivel de módulo. Lee el archivo,
  ignora líneas vacías y comentarios (`#`), valida cada dominio con
  `validate_domain()` (los inválidos se descartan con aviso, señalando el
  número de línea — no abortan la carga de toda la lista), y deduplica
  preservando el orden del archivo.
- **`-dL` / `--domain-list <archivo>`**: mutuamente excluyente con
  `-d`/`--domain` (`argparse.add_mutually_exclusive_group`).
- **`--domain-delay <segundos>`**: override puntual de la pausa entre
  dominios, sin tener que tocar `CONFIG`.
- **`BountyFlow.run()`** ganó el parámetro `show_banner: bool = True`. En
  modo batch el banner grande se imprime una sola vez antes del loop (no
  una vez por dominio — con 20+ dominios sería puro ruido), y cada
  `flow.run(show_banner=False)` arranca directo con su log de fases.
- **Resiliencia por dominio:** cada dominio corre dentro de su propio
  `try/except`. Si un dominio tira una excepción no controlada, se loguea,
  se cierra su logger, y el batch sigue con el siguiente dominio de la
  lista (en modo single-domain, sin `-dL`, el comportamiento viejo se
  mantiene: la excepción se re-lanza tal cual, para no esconder errores
  durante uso normal/debug).
- **Ctrl+C en medio de un batch:** se corta el dominio actual
  prolijamente (mismo manejo que ya existía para un solo dominio —
  resumen parcial, log cerrado), se cancelan los dominios restantes de la
  lista (no se sigue "a la fuerza"), y se muestra igual el resumen de
  batch con lo que sí se llegó a procesar.
- **`print_batch_summary()`**: tabla final con dominio, estado
  (ok/error/interrupted), y un vistazo rápido a subdominios/hosts
  vivos/hallazgos de takeover/hallazgos de nuclei por dominio — para no
  tener que ir carpeta por carpeta a ver cómo le fue a cada uno.

### Cómo se probó

Se armó un `domains.txt` sintético con una línea comentada, un dominio
duplicado y una línea con formato inválido, y se corrió con `--only grep`
(fase liviana, sin red) para validar la mecánica completa sin depender de
conectividad real:

```
# lista de prueba
a-fake-domain.test
b-fake-domain.test
not a domain!!
a-fake-domain.test
c-fake-domain.test
```

Resultado: cargó 3 dominios válidos (descartó la línea inválida con aviso
de número de línea, deduplicó el repetido), banner impreso una sola vez,
cada dominio corrió con su propia carpeta de salida (`out/a-fake-domain_
test/`, etc.), pausa de 1s respetada entre cada uno (`--domain-delay 1`), y
la tabla de resumen final mostró los 3 como "ok" con sus stats (en `-`
porque las fases de red estaban deshabilitadas por el `--only grep` del
test).

### Qué queda afuera (a propósito, por ahora)

- No hay un modo "N dominios en paralelo" — fue pedido explícitamente en
  contra de esto para no saturar la VPN. Si en el futuro se necesita correr
  más rápido en una red que sí lo banca, se podría agregar un
  `--parallel-domains N` opcional, pero no es el comportamiento default.
- `--domain-delay` y `CONFIG["vpn_safe"]["between_domains_delay"]` son fijos
  (no hay backoff adaptativo si la VPN empieza a tirar timeouts). Si se
  vuelve un problema real en uso, se podría encadenar con la idea de
  "reintentos con backoff" que ya está anotada en `ROADMAP.md`.
