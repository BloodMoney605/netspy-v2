# NetSpy

Herramienta de reconocimiento y busqueda de vulnerabilidades. Le das un
dominio y te devuelve los subdominios, los puertos abiertos, que tecnologia
corre en cada uno, que versiones tiene y que CVEs hay para esas
versiones.

Funciona en Linux, macOS y Windows.

```
recon  ->  puertos  ->  fingerprint  ->  CVEs  ->  reporte
 (1)        (2)          (3)            (4)        (5)
```

## Que se necesita

Python 3.9 o superior. Nada mas.

Las herramientas externas son opcionales. Cada una mejora el resultado, y
si no esta NetSpy sigue andando igual:

| Herramienta | Para que sirve | Que pasa si no esta |
|---|---|---|
| `nmap` | version de cada servicio | se usa el escaner TCP propio, que solo ve puertos |
| `httpx` | sondeo HTTP y deteccion de stack | se usa urllib |
| `openssl` | certificados y protocolos TLS | se salta la parte SSL |
| `whatweb` | fingerprint profundo | queda solo httpx |
| `nuclei` | plantillas | desactivado |
| `dig` | registros DNS completos | solo A y AAAA, por socket |
| `whois` | datos de registrante | consulta por socket al puerto 43 |

`netspy doctor` las instala.

## Instalar

### Windows

Doble clic en `install.bat`, o desde CMD:

```
git clone https://github.com/BloodMoney605/netspy-v2.git
cd netspy
install.bat
```

Despues:

```
netspy.bat                      menu interactivo
netspy.bat audit --domain ejemplo.com
netspy.bat doctor               instala lo que falte
netspy.bat selfcheck            diagnostica la maquina
```

Hace falta Python 3.9+ de [python.org](https://www.python.org/downloads/).
Hay que tildar "Add python.exe to PATH" en el instalador, si no `netspy.bat`
no lo encuentra.

Ojo: el archivo `netspy` sin extension es un script de bash y no corre en
Windows. Ahi se usa `netspy.bat` o `python netspy.py`.

### Linux y macOS

```
git clone https://github.com/BloodMoney605/netspy-v2.git
cd netspy
python3 install.py
```

`./install.sh` hace lo mismo.

Instalacion a mano, sin el script:

```
pip install -r requirements.txt
python netspy.py doctor
```

Que hace el instalador: crea el directorio de datos, instala PyYAML, y ofrece
instalar las herramientas opcionales. Se puede saltear cada parte:

```
python install.py --no-tools
python install.py --no-link
```

## Usar

Sin argumentos abre un menu. Con argumentos va directo:

```
netspy audit --domain ejemplo.com           pipeline completo, con reporte
netspy scan --domain ejemplo.com            idem sin el reporte
netspy recon --domain ejemplo.com           solo subdominios y DNS
netspy portscan --target 192.168.1.0/24     solo puertos
netspy report --dir output/ejemplo.com      arma el reporte de datos existentes
netspy doctor                               instala lo que falte
netspy selfcheck                            diagnostica la maquina
netspy clean                                borra cache y temporales
netspy version
netspy help
```

Opciones:

```
--domain     objetivo: ejemplo.com
--target     IP o rango CIDR
--config     otro archivo de configuracion
--output     carpeta de salida
--threads    cantidad de hilos
```

Ejemplo completo:

```
netspy audit --domain ejemplo.com --threads 50 --output ./resultados
```

## Donde quedan los archivos

```
output/<dominio>/
  recon.json        subdominios, IPs, DNS, WHOIS, ASN
  subdomains.txt    los subdominios que respondieron
  ips.txt           IPs unicas
  targets.txt       lo que entra a la fase 2
  ports.json        puertos abiertos y servicios
  services.txt      servicios sin JSON
  urls.txt          URLs para el fingerprint
  tech.json         tecnologias, versiones, headers
  findings.json     CVEs y hallazgos
  report.txt        reporte final (o report.json)
```

## Configuracion

El archivo esta en `config/default.yaml` y no tiene rutas de ninguna
computadora en particular, asi que el mismo sirve para cualquiera que clone el
repo.

```
--config /ruta/mi.yaml      para una corrida
NETSPY_CONFIG=/ruta/mi.yaml  para toda la sesion de shell
<data dir>/config.yaml       permanente, si existe tiene prioridad
```

El directorio de datos depende del sistema:

```
Linux     ~/.local/share/netspy
macOS     ~/Library/Application Support/netspy
Windows   %LOCALAPPDATA%\netspy
```

Con `NETSPY_HOME` se mueve todo de una vez.

Las claves, todas activas:

```yaml
target:
  threads: 20

recon:
  subdomains:
    wordlist: "subdomains.txt"   # un nombre, no una ruta
    sources:                     # cuales se consultan
      - crtsh
      - anubis
      - alienvault
      - wayback
    resolver: "1.1.1.1"

scan:
  ports:
    top: 200                      # cuantos puertos
  service_detect: true            # nmap -sV, mas lento pero ve versiones
  os_detect: false                # nmap -O, muy lento
  use_custom_scanner: false       # true = escaner TCP propio

fingerprint:
  extract_versions: true
  whatweb_limit: 10               # cuantos hosts pasan por whatweb

vuln:
  cve_db_path: "${NETSPY_HOME}/cve.db"
  nuclei_templates: "${NETSPY_HOME}/nuclei-templates"
  enable_nuclei: false            # usa mucha memoria
  severity_min: "medium"          # info, low, medium, high, critical

report:
  format: "txt"                   # txt o json
```

Sobre el wordlist: es un nombre. NetSpy lo busca en el directorio de datos,
junto al config y en la raiz del repo. Si no lo encuentra usa una lista
interna de unos 310 subdominidos comunes, asi que un clon nuevo no necesita
nada extra. Si pones tu archivo en cualquiera de esos tres lugares, se usa
solo.

`${NETSPY_HOME}` se expande al directorio de datos del sistema. Tambien valen
`~` y `$VARIABLE`.

## API key de NVD

NVD deja 5 peticiones cada 30 segundos sin key, y 50 con key. Auditar un
dominio con diez productos distintos se nota la diferencia.

La key es gratis: <https://nvd.nist.gov/developers/request-an-api-key>

```
export NETSPY_NVD_KEY=tu_clave
```

`netspy selfcheck` dice si esta puesta.

## Variables de entorno

```
NETSPY_CONFIG      config a usar
NETSPY_HOME        mueve el directorio de datos
NETSPY_LANG=es     salida en espanol
NETSPY_STEALTH     0, 1 o 2
NETSPY_TMP         carpeta temporal
NETSPY_VERBOSE     salida verbosa
NETSPY_DEBUG       muestra tambien los errores que se suelen callar
NETSPY_NVD_KEY     api key de NVD
NO_COLOR           saca los colores
```

## Como se detectan los CVEs

La fase 4 le pregunta a NVD usando CPE (`virtualMatchString`), o sea que le
pide "que CVEs afectan exactamente esta version" y NVD resuelve los rangos
por su cuenta. Es la fuente autoritativa, y los resultados coinciden con los
de NVD.

Cuando un producto no tiene CPE, se recurre a una busqueda por palabras
clave. Ahi NVD no dice que versiones estan afectadas, asi que el hallazgo
sale marcado como **no verificado** en la consola y en el reporte, para que
no se tome por confirmado sin revisarlo.

Un detalle que suele confundir: si el mismo CVE afecta dos versiones
detectadas, aparece una vez por cada una. No son duplicados, es que las dos
estan afectadas.

## Si algo falla

```
netspy selfcheck
```

Revisa el interprete, el encoding, si las carpetas se pueden escribir, la
config, las dependencias y el DNS. Cada linea dice que encontro y que hacer.
Lo que impide ejecutar devuelve codigo 1.

Con `NETSPY_DEBUG=1` tambien se ven los errores que en operacion normal se
ignoran, como que una fuente de red fallo o que la cache no se pudo
escribir.

## Tests

```
python3 test/check_imports.py       nombres usados sin importar
python3 test/test_core.py           matching de versiones, wordlist
python3 test/test_platform.py       ramas por sistema operativo
python3 test/test_nvd_accuracy.py   contra la API de NVD, necesita red
```

Los ultimos dos no tocan la red, asi que corren en cualquier parte. El de
NVD compara la salida con la respuesta de NVD para el mismo producto y
version.

## Estructura

```
netspy.py             arma el parser y despacha
lib/cli/              salida, idioma, menu, sigilo, procesos, comandos
lib/cve/              catalog, version, nvd, osv, match
lib/checks/           nuclei, ssl, misconfig
lib/subdomains/       fuentes, dns, whois, brute
lib/informe/          secciones del reporte
lib/netspy_env.py     rutas por SO, busqueda de binarios, procesos, terminal
lib/installer.py      instalación por gestor de paquetes
lib/config.py         carga del YAML

lib/recon.py          fase 1
lib/scan.py           fase 2
lib/fingerprint.py    fase 3
lib/vuln.py           fase 4
lib/report.py         fase 5
```

## Aviso

Esto es para auditar sistemas propios o con permiso escrito. Escanear o
reconocer infraestructura de terceros sin autorizacion es ilegal en la
mayoria de las jurisdicciones.

`output/` esta en `.gitignore` porque los reportes traen IPs, versiones y
CVEs de los objetivos. Si ese directorio se comparte por otro medio, asumi
que hay datos de terceros en el.

## Licencia

Ver [LICENSE](LICENSE).