# Efigalia KB — Especificación técnica completa

## Parte 1: Arquitectura, despliegue y API

### Arquitectura general

```
┌─────────────────────────────────┐
│   GitHub Pages                  │
│  (index.html + sw.js + assets)  │
│  Service Worker v21             │
└────────────┬────────────────────┘
             │ fetch() (CORS)
             ↓
┌─────────────────────────────────────────────┐
│  Cloudflare Worker                          │
│  efigalia-kb.efigalia-solar.workers.dev     │
│  ├─ Autenticación JWT (HS256, 24h TTL)     │
│  ├─ PBKDF2 PIN validation (100k iter)      │
│  ├─ API REST (6 entidades + admin)         │
│  ├─ ETag/If-Match (concurrencia optimista) │
│  ├─ Backups automáticos en R2              │
│  └─ Proxy a Anthropic API                  │
└────────────┬────────────────────────────────┘
             │
             ↓
    ┌────────────────────┐
    │   Cloudflare R2    │
    │   (Bucket: FOTOS)  │
    │ ├─ kb/data.json    │
    │ ├─ kb/partes.json  │
    │ ├─ kb/movimientos  │
    │ ├─ kb/visitas.json │
    │ ├─ kb/materiales   │
    │ ├─ kb/_backups/    │
    │ └─ fotos/          │
    └────────────────────┘
```

### Variables de entorno del Worker (Cloudflare)

| Variable | Tipo | Requerida | Descripción |
|----------|------|-----------|-------------|
| `JWT_SECRET` | string | Sí | Clave para firmar JWT (mín. 32 chars) |
| `ANTHROPIC_API_KEY` | string | Sí | API key de Anthropic (sk-ant-...) |
| `FOTOS` | R2 Binding | Sí | Binding al bucket R2 (no es env var, se configura en Workers) |
| `BOOTSTRAP_PIN` | string | No | PIN temporal ≥8 chars para primer admin (borrar tras uso) |
| `BOOTSTRAP_ADMIN_NAME` | string | No | Nombre del admin para bootstrap (borrar tras uso) |

### Flujo de autenticación

1. **Login** → `POST /auth/login` con `{nombre, pin}`
   - Worker busca usuario en `kb/data.json` (tipo: "instalador", activa ≠ false)
   - Valida PIN contra PBKDF2-SHA256 (100k iter, sal 16 bytes por usuario)
   - Devuelve JWT firmado HS256 (exp: 24h) con `{sub: nombre, rol: "admin"|"instalador"|"ambos"}`
2. **Cliente** almacena token en `sessionStorage.efigalia_token`
3. **Cada petición** envía `Authorization: Bearer <token>`
4. **401** → cliente limpia sesión y muestra login

### Endpoints API

| Método | Ruta | Auth | Descripción |
|--------|------|------|-------------|
| GET | `/foto/:key` | No | Servir imagen/PDF desde R2 |
| GET | `/auth/users` | No | Lista de nombres para dropdown de login |
| POST | `/auth/login` | No | Autenticación → JWT |
| POST | `/auth/change-pin` | Sí | Cambiar propio PIN (exige actual) |
| POST | `/auth/set-pin` | Admin | Asignar PIN a otro usuario |
| GET | `/data` | Sí | Leer datos maestros (redacta PINs, devuelve ETag) |
| POST | `/data` | Admin | Guardar datos maestros (overwrite + If-Match + merge PINs) |
| GET | `/partes` | Sí | Leer partes de trabajo |
| POST | `/partes` | Sí | **Merge por id** (nunca se pierden datos de otros) |
| GET | `/movimientos` | Sí | Leer movimientos de almacén |
| POST | `/movimientos` | Sí | **Merge por id** |
| GET | `/visitas` | Sí | Leer visitas pre-contrato |
| POST | `/visitas` | Sí | Overwrite con If-Match |
| GET | `/materiales` | Sí | Leer catálogo de materiales |
| POST | `/materiales` | Sí | Overwrite con If-Match |
| POST | `/foto` | Sí | Upload imagen (máx 10 MB; jpg/png/webp) |
| POST | `/ai` | Sí | Proxy a API Anthropic |
| GET | `/admin/orphans?kind=pdf\|photo` | Admin | Listar archivos huérfanos en R2 |
| POST | `/admin/delete-objects` | Admin | Borrar objetos huérfanos (con verificación) |

### Estructura R2

```
kb/
├── data.json              (maestros: usuarios, obras, clientes, incidencias, asignaciones...)
├── partes.json            (partes de obra)
├── movimientos.json       (movimientos de materiales)
├── visitas.json           (visitas pre-contrato FV y PdR)
├── materiales.json        (catálogo de materiales)
└── _backups/
    ├── data-2026-05-26T12-34-56.json
    ├── partes-2026-05-26T13-45-00.json
    └── ...

fotos/
├── 1716744296123_abc123.jpg
├── 1716744297456_def456.pdf
└── ...
```

### Service Worker (estrategia de caché)

- **Network-first** para HTML (index.html) → fallback a caché offline
- **Cache-first** para assets estáticos (iconos, manifest, pdf.js)
- **Never cache** las llamadas al Worker API (.workers.dev)
- Versión en constante `VERSION` (actual: v21). Cada cambio la bumpa para invalidar caché
- `updateViaCache: 'none'` + `SKIP_WAITING` + `controllerchange` → reload automático

### Despliegue paso a paso

1. **Cloudflare Workers**: crear worker, añadir binding R2 (FOTOS), configurar env vars
2. **Pegar `worker/index.js`** en Edit code → Save and deploy
3. **GitHub Pages**: branch main, root directory. Sirve index.html + sw.js + assets
4. **CORS**: worker solo permite `https://efigaliasolar-droid.github.io`
5. **First run**: si BOOTSTRAP_PIN activo → login → cambiar PIN → borrar env vars

---

## Parte 2: Cálculos rápidos — Especificación completa de fórmulas

La app tiene 4 calculadoras independientes. Cada una recibe inputs del usuario, aplica fórmulas/tablas y devuelve resultados. A continuación se detalla TODO lo necesario para reimplementarlas.

---

### 2.1 Sección de cable AC (inversor → cuadro)

**Propósito**: dimensionar el cable AC desde la salida del inversor por intensidad admisible y caída de tensión (máx 1,5%).

#### Inputs

| Campo | Tipo | Opciones / Rango | Unidad |
|-------|------|------------------|--------|
| Marca inversor | select | Huawei, Sigenergy, SolarEdge | — |
| Modelo inversor | select | dinámico según marca | — |
| Imax AC | number (autorellenado del modelo) | > 0 | A |
| Longitud cable | number | ≥ 1 | m |
| Método de instalación | select | B = bajo tubo en pared, D = bajo tubo enterrado | — |

#### Constantes

**Conductividad del cobre:**
```
γ_Cu = 56 m/(Ω·mm²) a 20 °C
```

**Secciones comerciales disponibles (mm²):**
```
[1.5, 2.5, 4, 6, 10, 16, 25, 35, 50, 70, 95, 120, 150, 185, 240, 300, 400]
```

**Tabla de intensidades admisibles (ITC-BT-19, Cu XLPE 40°C):**

| Sección (mm²) | 1.5 | 2.5 | 4 | 6 | 10 | 16 | 25 | 35 | 50 | 70 | 95 | 120 | 150 | 185 | 240 | 300 | 400 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **Método B mono** | 17.5 | 24 | 32 | 41 | 57 | 76 | 101 | 125 | 151 | 192 | 232 | 269 | 309 | 353 | 415 | 488 | 563 |
| **Método B tri** | 15.5 | 21 | 28 | 36 | 50 | 68 | 89 | 110 | 134 | 171 | 207 | 239 | 275 | 314 | 369 | 434 | 501 |
| **Método D mono** | 22 | 29 | 38 | 47 | 63 | 81 | 104 | 125 | 148 | 183 | 216 | 246 | 278 | 312 | 361 | 418 | 478 |
| **Método D tri** | 18 | 24 | 31 | 39 | 52 | 67 | 86 | 103 | 122 | 151 | 179 | 203 | 230 | 258 | 297 | 344 | 394 |

**Tabla de inversores (marca → modelo → tipo + Imax):**

*Huawei:*
| Modelo | Tipo | Imax (A) |
|--------|------|----------|
| SUN2000-2KTL-L1 | mono | 10 |
| SUN2000-3KTL-L1 | mono | 16 |
| SUN2000-3.68KTL-L1 | mono | 16 |
| SUN2000-4KTL-L1 | mono | 20 |
| SUN2000-4.6KTL-L1 | mono | 22.8 |
| SUN2000-5KTL-L1 | mono | 25 |
| SUN2000-6KTL-L1 | mono | 27 |
| SUN2000-3KTL-M1 | tri | 4.8 |
| SUN2000-4KTL-M1 | tri | 6.5 |
| SUN2000-5KTL-M1 | tri | 8 |
| SUN2000-6KTL-M1 | tri | 9.5 |
| SUN2000-8KTL-M1 | tri | 13 |
| SUN2000-10KTL-M1 | tri | 16 |
| SUN2000-12KTL-M1 | tri | 19 |
| SUN2000-15KTL-M1 | tri | 23.5 |
| SUN2000-17KTL-M1 | tri | 26.5 |
| SUN2000-20KTL-M1 | tri | 31 |
| SUN2000-25KTL-M5 | tri | 38 |
| SUN2000-30KTL-M3 | tri | 45 |
| SUN2000-36KTL-M3 | tri | 54 |
| SUN2000-40KTL-M3 | tri | 60 |
| SUN2000-50KTL-M3 | tri | 76 |
| SUN2000-100KTL-M1 | tri | 152 |

*Sigenergy:*
| Modelo | Tipo | Imax (A) |
|--------|------|----------|
| SigenStor EC 3.0 SP | mono | 16 |
| SigenStor EC 4.0 SP | mono | 20 |
| SigenStor EC 5.0 SP | mono | 25 |
| SigenStor EC 6.0 SP | mono | 28.6 |
| SigenStor EC 8.0 SP | mono | 36.4 |
| SigenStor EC 5.0 TP | tri | 8 |
| SigenStor EC 6.0 TP | tri | 9.5 |
| SigenStor EC 8.0 TP | tri | 12.5 |
| SigenStor EC 10.0 TP | tri | 15.5 |
| SigenStor EC 12.0 TP | tri | 18.5 |
| SigenStor EC 15.0 TP | tri | 23 |
| SigenStor EC 17.0 TP | tri | 26 |
| SigenStor EC 20.0 TP | tri | 30.5 |
| SigenStor EC 25.0 TP | tri | 38 |

*SolarEdge:*
| Modelo | Tipo | Imax (A) |
|--------|------|----------|
| SE2200H | mono | 11 |
| SE3000H | mono | 13 |
| SE3500H | mono | 17 |
| SE4000H | mono | 18 |
| SE5000H | mono | 22 |
| SE6000H | mono | 27 |
| SE3K | tri | 4.5 |
| SE4K | tri | 6 |
| SE5K | tri | 7.5 |
| SE7K | tri | 11.5 |
| SE8K | tri | 13 |
| SE10K | tri | 16 |
| SE12.5K | tri | 20 |
| SE15K | tri | 23.5 |
| SE16K | tri | 25.5 |
| SE17K | tri | 27 |
| SE25K | tri | 38.5 |
| SE27.6K | tri | 42 |
| SE33.3K | tri | 50 |
| SE40K | tri | 61 |
| SE50K | tri | 76 |
| SE55K | tri | 85 |
| SE66.6K | tri | 101.5 |
| SE82.8K | tri | 126 |
| SE90K | tri | 136 |
| SE100K | tri | 152 |

#### Fórmulas paso a paso

```
1. Tensión nominal:
   V = 400 V (trifásico) ó 230 V (monofásico)
   Se determina por inv.tipo ('tri' o 'mono')

2. Caída de tensión máxima admisible:
   ΔV_max = 0.015 × V

3. Corriente de diseño (factor REBT):
   I_diseño = Imax × 1.25

4. Sección mínima por caída de tensión:
   Monofásico:  S_cdt = (2 × L × Imax) / (γ × ΔV_max)
   Trifásico:   S_cdt = (√3 × L × Imax) / (γ × ΔV_max)
   → Redondear al alza a la primera sección comercial ≥ S_cdt

5. Sección mínima por intensidad admisible:
   S_I = primera sección cuya I_adm ≥ I_diseño
   (buscar en la tabla IADM[método][mono/tri])

6. Sección recomendada:
   S_rec = max(S_cdt, S_I)

7. Caída de tensión real con S_rec:
   Monofásico:  ΔV_real = (2 × L × Imax) / (γ × S_rec)
   Trifásico:   ΔV_real = (√3 × L × Imax) / (γ × S_rec)
   cdt% = (ΔV_real / V) × 100
```

#### Outputs

- Sección recomendada (mm² Cu)
- Caída de tensión real (%)
- Sección mínima por intensidad
- Sección mínima por cdt
- Corriente de diseño (A)

---

### 2.2 Calibre de protecciones AC

**Propósito**: determinar magnetotérmico y diferencial para la salida AC del inversor.

#### Inputs

Igual que cable AC + campo adicional:
| Campo | Tipo | Opciones |
|-------|------|----------|
| Tipo de instalación | select | res = Residencial (30 mA), com = Comercial (300 mA) |

#### Constantes

**Calibres estándar de magnetotérmico (A):**
```
[6, 10, 16, 20, 25, 32, 40, 50, 63, 80, 100, 125, 160]
```

#### Fórmulas

```
1. Magnetotérmico:
   MCB = primer calibre estándar ≥ Imax del inversor
   (SIN factor 1.25: los inversores están limitados electrónicamente)
   Curva C
   Polos: 4P (trifásico) ó 2P (monofásico)

2. Diferencial:
   Si MCB ≤ 40 A → RCD = 40 A
   Si MCB ≤ 63 A → RCD = 63 A
   Si MCB > 63 A → Relé diferencial + toroidal
   Si MCB > 160 A → Relé diferencial + toroidal

   Tipo A
   Sensibilidad: 30 mA (residencial) ó 300 mA (comercial/industrial)
   Polos: 4P (trifásico) ó 2P (monofásico)
```

---

### 2.3 Sección de cable DC (paneles → inversor)

**Propósito**: dimensionar el cable DC del string fotovoltaico por intensidad y caída de tensión (máx 1,5%).

#### Inputs

| Campo | Tipo | Opciones / Rango | Unidad |
|-------|------|------------------|--------|
| Marca inversor | select | Huawei, Sigenergy, SolarEdge | — |
| Modelo inversor | select | dinámico según marca | — |
| Panel solar | select | (ver tabla de paneles) | — |
| Nº paneles en serie | number | ≥ 1 | ud |
| Longitud cable | number | ≥ 1 | m |

#### Constantes

**Paneles solares:**
| Modelo | Pot (W) | Voc (V) | Isc (A) | Vmp (V) | Imp (A) | Coef Voc (%/°C) |
|--------|---------|---------|---------|---------|---------|-----------------|
| Longi LR7-60HVH-535M | 535 | 44.78 | 15.15 | 37.01 | 14.46 | -0.24 |

**Secciones DC disponibles (cable solar H1Z2Z2-K 1500V):**
```
[4, 6, 10] mm²
```

**Intensidades admisibles DC (UNE-EN 50618, 60°C ambiente):**
| 4 mm² | 6 mm² | 10 mm² |
|-------|-------|--------|
| 55 A | 70 A | 98 A |

**Temperatura mínima para Voc:** T_min = -10 °C

**Rangos MPPT de inversores:**

*Huawei:*
| Modelo | Vmin (V) | Vmax (V) | Vdc max (V) | I string (A) |
|--------|----------|----------|-------------|---------------|
| SUN2000-2KTL-L1 | 90 | 560 | 600 | 11 |
| SUN2000-3KTL-L1 | 90 | 560 | 600 | 11 |
| SUN2000-3.68KTL-L1 | 90 | 560 | 600 | 13.5 |
| SUN2000-4KTL-L1 | 90 | 560 | 600 | 13.5 |
| SUN2000-4.6KTL-L1 | 90 | 560 | 600 | 13.5 |
| SUN2000-5KTL-L1 | 90 | 560 | 600 | 13.5 |
| SUN2000-6KTL-L1 | 90 | 560 | 600 | 13.5 |
| SUN2000-3KTL-M1 | 140 | 980 | 1100 | 13.5 |
| SUN2000-4KTL-M1 | 140 | 980 | 1100 | 13.5 |
| SUN2000-5KTL-M1 | 140 | 980 | 1100 | 13.5 |
| SUN2000-6KTL-M1 | 140 | 980 | 1100 | 13.5 |
| SUN2000-8KTL-M1 | 140 | 980 | 1100 | 13.5 |
| SUN2000-10KTL-M1 | 140 | 980 | 1100 | 13.5 |
| SUN2000-12KTL-M1 | 160 | 950 | 1100 | 22 |
| SUN2000-15KTL-M1 | 160 | 950 | 1100 | 22 |
| SUN2000-17KTL-M1 | 160 | 950 | 1100 | 22 |
| SUN2000-20KTL-M1 | 160 | 950 | 1100 | 22 |
| SUN2000-25KTL-M5 | 200 | 1000 | 1100 | 26 |
| SUN2000-30KTL-M3 | 200 | 1000 | 1100 | 26 |
| SUN2000-36KTL-M3 | 200 | 1000 | 1100 | 26 |
| SUN2000-40KTL-M3 | 200 | 1000 | 1100 | 26 |
| SUN2000-50KTL-M3 | 200 | 1000 | 1100 | 26 |
| SUN2000-100KTL-M1 | 200 | 1000 | 1100 | 26 |

*Sigenergy:*
| Modelo | Vmin (V) | Vmax (V) | Vdc max (V) | I string (A) |
|--------|----------|----------|-------------|---------------|
| SigenStor EC 5.0 TP | 150 | 850 | 1000 | 16 |
| SigenStor EC 6.0 TP | 150 | 850 | 1000 | 16 |
| SigenStor EC 8.0 TP | 150 | 850 | 1000 | 16 |
| SigenStor EC 10.0 TP | 150 | 850 | 1000 | 16 |
| SigenStor EC 12.0 TP | 150 | 850 | 1000 | 16 |
| SigenStor EC 15.0 TP | 200 | 850 | 1000 | 16 |
| SigenStor EC 17.0 TP | 200 | 850 | 1000 | 16 |
| SigenStor EC 20.0 TP | 200 | 850 | 1000 | 16 |
| SigenStor EC 25.0 TP | 200 | 850 | 1000 | 16 |

*(SolarEdge no tiene tabla MPPT: usa tensión fija regulada por optimizadores)*

#### Fórmulas paso a paso

```
CASO A — SolarEdge (tensión fija por optimizadores):
   V_string = 750 V (trifásico) ó 380 V (monofásico)
   P_total = n × Pot_panel
   I_operación = P_total / V_string
   I_diseño = I_operación × 1.25

CASO B — Inversores de string (Huawei, Sigenergy):
   V_string = n × Vmp
   Voc_string = n × Voc
   Voc(T_min) = Voc_string × (1 + (coef_voc / 100) × (T_min - 25))
   I_operación = Imp del panel
   I_diseño = Isc × 1.25

   Verificaciones MPPT:
   ✓ Voc(T_min) ≤ Vdc_max del inversor
   ✓ V_string ≥ Vmin MPPT y V_string ≤ Vmax MPPT
   ✓ Isc ≤ I_max_string del inversor

COMÚN (ambos casos):
   ΔV_max = 0.015 × V_string
   S_cdt = (2 × L × I_operación) / (γ × ΔV_max)
   → Redondear al alza a sección comercial DC [4, 6, 10]

   S_I = primera sección cuya I_adm_DC ≥ I_diseño

   S_rec = max(S_cdt, S_I)

   ΔV_real = (2 × L × I_operación) / (γ × S_rec)
   cdt% = (ΔV_real / V_string) × 100
```

Si ninguna sección DC cubre ambos criterios → error: "reducir longitud, dividir string o rediseñar".

---

### 2.4 Instalación aislada (Victron + BYD)

**Propósito**: dimensionar cables DC, fusibles y protecciones AC de un sistema off-grid completo con bus DC de 48 V.

#### Inputs

| Campo | Tipo | Opciones |
|-------|------|----------|
| Inversor/cargador Victron | select | ver tabla |
| Regulador MPPT Victron | select | ver tabla |
| Batería BYD | select | ver tabla |

#### Tablas de equipos

**Victron MultiPlus-II / Quattro:**
| Modelo | V bat | P cont (W) | I DC (A) | Cable DC (mm²) | Fusible DC (A) | I AC (A) | Tipo |
|--------|-------|------------|----------|----------------|----------------|----------|------|
| MultiPlus-II 48/3000/35 | 48 | 2400 | 60 | 35 | 125 | 13 | mono |
| MultiPlus-II 48/5000/70 | 48 | 4000 | 100 | 50 | 200 | 21.7 | mono |
| MultiPlus-II 48/8000/110 | 48 | 6500 | 140 | 95 | 300 | 35 | mono |
| MultiPlus-II 48/10000/140 | 48 | 8000 | 180 | 2×50 ó 120 | 400 | 43.5 | mono |
| MultiPlus-II 48/15000/200 | 48 | 12000 | 250 | 2×70 ó 150 | 500 | 52 | mono |
| Quattro 48/5000/70 | 48 | 4000 | 100 | 50 | 200 | 21.7 | mono |
| Quattro 48/8000/110 | 48 | 6500 | 140 | 95 | 300 | 35 | mono |
| Quattro 48/10000/140 | 48 | 8000 | 180 | 2×50 ó 120 | 400 | 43.5 | mono |
| Quattro 48/15000/200 | 48 | 12000 | 250 | 2×70 ó 150 | 500 | 52 | mono |

**Victron SmartSolar MPPT:**
| Modelo | V max (V) | I max (A) | Cable (mm²) | Fusible (A) |
|--------|-----------|-----------|-------------|-------------|
| SmartSolar MPPT 75/15 | 75 | 15 | 4 | 25 |
| SmartSolar MPPT 100/20 | 100 | 20 | 6 | 30 |
| SmartSolar MPPT 100/30 | 100 | 30 | 10 | 40 |
| SmartSolar MPPT 100/50 | 100 | 50 | 16 | 63 |
| SmartSolar MPPT 150/35 | 150 | 35 | 10 | 50 |
| SmartSolar MPPT 150/45 | 150 | 45 | 16 | 63 |
| SmartSolar MPPT 150/60 | 150 | 60 | 16 | 80 |
| SmartSolar MPPT 150/70 | 150 | 70 | 25 | 100 |
| SmartSolar MPPT 150/85 | 150 | 85 | 25 | 125 |
| SmartSolar MPPT 150/100 | 150 | 100 | 35 | 125 |
| SmartSolar MPPT 250/60 | 250 | 60 | 16 | 80 |
| SmartSolar MPPT 250/85 | 250 | 85 | 25 | 125 |
| SmartSolar MPPT 250/100 | 250 | 100 | 35 | 125 |

**BYD Battery-Box Premium LV:**
| Modelo | V (V) | Capacidad (kWh) | I max (A) | Fusible rec. (A) | Módulos |
|--------|-------|-----------------|-----------|-------------------|---------|
| Battery-Box Premium LVS 4.0 | 48 | 4.0 | 100 | 125 | 1 |
| Battery-Box Premium LVS 8.0 | 48 | 8.0 | 200 | 250 | 2 |
| Battery-Box Premium LVS 12.0 | 48 | 12.0 | 250 | 300 | 3 |
| Battery-Box Premium LVS 16.0 | 48 | 16.0 | 250 | 300 | 4 |
| Battery-Box Premium LVS 20.0 | 48 | 20.0 | 250 | 300 | 5 |
| Battery-Box Premium LVS 24.0 | 48 | 24.0 | 250 | 300 | 6 |
| Battery-Box Premium LVL 15.4 | 48 | 15.4 | 300 | Clase T 300 A | 1 |

**Tabla cable batería por corriente:**
| I max batería | Cable recomendado |
|---------------|-------------------|
| ≤ 50 A | 10 mm² |
| ≤ 80 A | 16 mm² |
| ≤ 125 A | 25 mm² |
| ≤ 160 A | 35 mm² |
| ≤ 200 A | 50 mm² |
| ≤ 250 A | 70 mm² |
| ≤ 300 A | 95 mm² |
| ≤ 400 A | 2×70 ó 120 mm² |
| > 400 A | 2×95 ó 150 mm² |

#### Cálculo

```
Sistema: bus DC 48 V

Tramo Inversor ↔ Embarrado:
   Cable DC = valor de tabla VICTRON_INV[modelo].cable_dc (para ≤ 5 m)
   Fusible DC = valor de tabla VICTRON_INV[modelo].fusible_dc

Tramo Batería ↔ Embarrado:
   Cable DC = lookup por bat.imax en tabla cableBatería
   Fusible DC = valor de tabla BYD_BAT[modelo].fus_rec

Tramo Regulador ↔ Embarrado:
   Cable DC = valor de tabla VICTRON_MPPT[modelo].cable (para ≤ 5 m)
   Fusible DC = valor de tabla VICTRON_MPPT[modelo].fusible

Protección AC (salida del inversor):
   I_diseño_AC = inv.iac × 1.25
   Magnetotérmico = primer calibre estándar ≥ I_diseño_AC (curva C)
   Diferencial = misma lógica que calculadora de protecciones AC (§2.2)
```

---

### Resumen de fórmulas clave

| Cálculo | Fórmula | Variables |
|---------|---------|-----------|
| Caída de tensión AC mono | ΔV = (2 × L × I) / (γ × S) | L=m, I=A, γ=56, S=mm² |
| Caída de tensión AC tri | ΔV = (√3 × L × I) / (γ × S) | L=m, I=A, γ=56, S=mm² |
| Caída de tensión DC | ΔV = (2 × L × I) / (γ × S) | L=m, I=A, γ=56, S=mm² |
| Sección por cdt (mono) | S = (2 × L × I) / (γ × ΔV_max) | ΔV_max = 0.015 × V |
| Sección por cdt (tri) | S = (√3 × L × I) / (γ × ΔV_max) | ΔV_max = 0.015 × V |
| Corriente de diseño | I_diseño = I_max × 1.25 | Factor REBT |
| Voc a temperatura mínima | Voc(T) = Voc₂₅ × (1 + coef/100 × (T - 25)) | T=-10°C, coef=%/°C |
| Corriente SolarEdge | I = P_total / V_string | V=750V(tri) ó 380V(mono) |
