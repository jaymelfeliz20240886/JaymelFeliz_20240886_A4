*VIDEO:*

# Auditoría y Endurecimiento (Hardening) Automatizado Basado en CIS Benchmarks

**Identificador / Matrícula:** `20240886`  
**Plataforma de Simulación:** GNS3 (Cisco IOSv / IOSvL2, FortiGate VM 7.0.9, Ubuntu Cloud 24.10)  
**Herramienta de Automatización:** Python 3 + Netmiko (`cis_hardening_tool.py`)

---

## Índice

1. [Propósito del Laboratorio](#1-propósito-del-laboratorio)
2. [Topología de Red y Arquitectura](#2-topología-de-red-y-arquitectura)
3. [Tabla de Direccionamiento IP](#3-tabla-de-direccionamiento-ip)
4. [Diario de Configuración y Troubleshooting Operativo](#4-diario-de-configuración-y-troubleshooting-operativo)
5. [Configuraciones Implementadas Paso a Paso](#5-configuraciones-implementadas-paso-a-paso)
6. [Políticas de Seguridad (Firewall Policies)](#6-políticas-de-seguridad-firewall-policies)
7. [Validación y Pruebas Analíticas](#7-validación-y-pruebas-analíticas)
8. [Diagramas y Evidencias Visuales](#8-diagramas-y-evidencias-visuales)
9. [Running Configurations Completas](#9-running-configurations-completas)
10. [Scripts y Archivos Utilizados](#10-scripts-y-archivos-utilizados)
11. [Conclusión](#11-conclusión)

---

## 1. Propósito del Laboratorio
<img width="816" height="747" alt="imagen" src="https://github.com/user-attachments/assets/1f5e0b2b-b045-479f-8991-917082ab75b1" />

El objetivo de este laboratorio es diseñar, implementar y auditar de forma automatizada una arquitectura de red empresarial endurecida bajo las recomendaciones internacionales del **Center for Internet Security (CIS Benchmarks)** para sistemas **Cisco IOS** y **Fortinet FortiGate**.

Mediante el desarrollo de un motor de auditoría y remediación en **Python** con la librería **Netmiko**, se busca:
* Eliminar vectores de ataque comunes en planos de gestión (protocolos en texto plano como Telnet y HTTP, ausencia de bloqueo ante fuerza bruta, tiempos de sesión ilimitados y protocolos de descubrimiento expuestos).
* Automatizar la evaluación inicial (*Dry-Run*) y la aplicación homogénea de políticas de seguridad en dispositivos heterogéneos.
* Generar evidencia documental auditable antes y después del endurecimiento, alcanzando el **100% de cumplimiento** sin interrumpir el enrutamiento ni el acceso hacia Internet.

---

## 2. Topología de Red y Arquitectura

La infraestructura se segmenta en tres zonas funcionales:
1. **Zona LAN / Gestión (`192.168.50.0/24`):** Compuesta por la estación de auditoría Linux (`PC`), el switch de distribución (`SW1`) y la interfaz interna del router perimetral (`R1`).
   <img width="546" height="433" alt="imagen" src="https://github.com/user-attachments/assets/4af30c20-82ba-4bc2-9c5d-5181b15f010b" />

3. **Zona de Tránsito / Enlace Punto a Punto (`172.16.10.0/30`):** Interconexión dedicada entre el router de borde (`R1`) y la interfaz interna (`port1`) del firewall perimetral (`FortiGate`).
   <img width="516" height="220" alt="imagen" src="https://github.com/user-attachments/assets/ecf7ea73-7f48-4b4f-bc0a-2fb1750cfd50" />

5. **Zona WAN / Salida Externa (`NAT1`):** Interfaz externa (`port2`) del firewall conectada al nodo `NAT1` de GNS3 mediante asignación dinámica DHCP y traducción de direcciones (SNAT).
   <img width="598" height="454" alt="imagen" src="https://github.com/user-attachments/assets/81674283-f690-41d2-92df-64dd4ff406fb" />


```text
                       [ Nube NAT1 (Internet) ]
                                  │ (DHCP)
                            ┌─────┴─────┐
                            │   port2   │
                            │ FortiGate │ (FW-CIS-20240886)
                            │   port1   │
                            └─────┬─────┘
                                  │ 172.16.10.1/30
                                  │
                                  │ 172.16.10.2/30
                            ┌─────┴─────┐
                            │    f0/0   │
                            │     R1    │ (Router Perimetral)
                            │    f1/0   │
                            └─────┬─────┘
                                  │ 192.168.50.1/24
                                  │
                            ┌─────┴─────┐
                            │   Gi0/0   │
                            │    SW1    │ (Switch Distribución)
                            │   Gi0/1   │
                            └─────┬─────┘
                                  │
                            ┌─────┴─────┐
                            │    e0     │
                            │    PC     │ (Ubuntu Cloud - Estación Auditora)
                            └───────────┘
                              192.168.50.10/24
```

---

## 3. Tabla de Direccionamiento IP

| Dispositivo | Hostname | Interfaz | Dirección IP | Máscara de Subred | Gateway / Siguiente Salto | Rol en la Red |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **PC (Ubuntu)** | `ubuntu-cloud` | `ens3` / `e0` | `192.168.50.10` | `255.255.255.0` (`/24`) | `192.168.50.1` | Estación de Auditoría y Automatización |
| **SW1** | `SW1` | `Vlan1` | `192.168.50.2` | `255.255.255.0` (`/24`) | `192.168.50.1` | Conmutación Capa 2 y Gestión LAN |
| **R1** | `R1` | `FastEthernet1/0` | `192.168.50.1` | `255.255.255.0` (`/24`) | N/A (Directamente conectada) | Puerta de Enlace LAN |
| **R1** | `R1` | `FastEthernet0/0` | `172.16.10.2` | `255.255.255.252` (`/30`) | `172.16.10.1` | Enlace Punto a Punto hacia Firewall |
| **FortiGate** | `FW-CIS-20240886` | `port1` | `172.16.10.1` | `255.255.255.252` (`/30`) | `172.16.10.2` (Ruta hacia LAN) | Interfaz Interna (Trust / LAN) |
| **FortiGate** | `FW-CIS-20240886` | `port2` | Dinámica (DHCP) | Dinámica (DHCP) | Dinámica (`NAT1`) | Interfaz Externa (Untrust / WAN) |

---

## 4. Diario de Configuración y Troubleshooting Operativo

Durante el despliegue y las pruebas de integración se documentaron y resolvieron las siguientes incidencias técnicas:

| # | Incidencia Detectada | Diagnóstico / Causa Raíz | Resolución Aplicada |
| :--- | :--- | :--- | :--- |
| **1** | **Inversión física de interfaces en FortiGate y falta de enlace con R1** | Mediante captura de tráfico (`diagnose sniffer packet port1 arp`) se detectó que `port1` recibía peticiones ARP de `172.16.10.2` (R1) mientras `port2` apuntaba a la nube externa. Además, inicialmente se utilizó `Cloud1` sin interfaz puenteada. | Se reemplazó `Cloud1` por el nodo `NAT1` en `port2`, se enlazó `R1 (f0/0)` con `FortiGate (port1)` y se reasignaron las subredes (`172.16.10.1/30` en `port1` y DHCP en `port2`). |
| **2** | **Fallo de resolución DNS en Ubuntu (`Temporary failure in name resolution`)** | El enlace simbólico de `systemd-resolved` sobrescribía `/etc/resolv.conf` sin servidores DNS válidos tras configurar la IP estática. | Se reemplazó `/etc/resolv.conf` fijando `nameserver 8.8.8.8`, restableciendo la resolución de dominios (`ping google.com`). |
| **3** | **Error `404 Not Found` en `apt update` (Ubuntu 24.10 Oracular)** | La versión `oracular` alcanzó el fin de soporte estándar y Canonical trasladó sus paquetes a los servidores de archivo histórico. | Se actualizaron las fuentes APT hacia `old-releases.ubuntu.com`, permitiendo instalar `python3-pip` y `netmiko`. |
| **4** | **Incompatibilidad de algoritmos SSH con Cisco IOS (`no acceptable kex algorithm`)** | Las versiones modernas de OpenSSH y Paramiko deshabilitan por defecto algoritmos SHA-1 heredados (`diffie-hellman-group14-sha1`, `ssh-rsa`) requeridos por Cisco IOSv. | Se configuró `~/.ssh/config` para pruebas manuales y se fijó **`paramiko==2.12.0`** en el entorno Python para compatibilidad nativa con Cisco IOS y FortiOS. |
| **5** | **Rechazo de autenticación en FortiGate tras reinicio de fábrica** | Tras ejecutar `execute factoryreset`, la contraseña del usuario `admin` quedó vacía y no coincidía con la credencial esperada por el script. | Se sincronizó la contraseña del administrador mediante `config system admin` (`set password cisco`) y se validó la recuperación mediante cuenta `maintainer`. |

---

## 5. Configuraciones Implementadas Paso a Paso

### 5.1. Configuración Base de Red y Enrutamiento

#### Router `R1`
```cisco
hostname R1
!
interface FastEthernet0/0
 description ENLACE_WAN_FORTIGATE
 ip address 172.16.10.2 255.255.255.252
 no shutdown
!
interface FastEthernet1/0
 description GATEWAY_LAN_GESTION
 ip address 192.168.50.1 255.255.255.0
 no shutdown
!
ip route 0.0.0.0 0.0.0.0 172.16.10.1
!
ip domain-name lab.local
crypto key generate rsa modulus 2048
username admin privilege 15 secret cisco
```

#### Switch `SW1`
```cisco
hostname SW1
!
interface Vlan1
 ip address 192.168.50.2 255.255.255.0
 no shutdown
!
ip default-gateway 192.168.50.1
!
ip domain-name lab.local
crypto key generate rsa modulus 2048
username admin privilege 15 secret cisco
```

#### Firewall `FortiGate` (`FW-CIS-20240886`)
```fortios
config system global
    set hostname "FW-CIS-20240886"
end
config system interface
    edit "port1"
        set mode static
        set ip 172.16.10.1 255.255.255.252
        set allowaccess ping https ssh
    next
    edit "port2"
        set mode dhcp
        set allowaccess ping
        set defaultgw enable
    next
end
config router static
    edit 1
        set dst 192.168.50.0 255.255.255.0
        set gateway 172.16.10.2
        set device "port1"
    next
end
```

### 5.2. Controles de Hardening CIS Benchmark Aplicados

#### Matriz CIS Benchmark para Cisco IOS (`R1` y `SW1`)

| ID Control CIS | Recomendación Técnica | Riesgo Mitigado y Justificación | Comandos Aplicados |
| :--- | :--- | :--- | :--- |
| **CIS-IOS-1.1.1** | Habilitar cifrado global de contraseñas | Evita la exposición de credenciales en texto plano dentro de `running-config` o respaldos exportados. | `service password-encryption` |
| **CIS-IOS-1.2.1** | Exigir SSH Versión 2 | Elimina vulnerabilidades criptográficas presentes en SSHv1 (ataques MitM e inserción de paquetes). | `ip ssh version 2` |
| **CIS-IOS-1.2.3** | Transporte exclusivo SSH y timeout en VTY/Consola | Bloquea el acceso por Telnet y cierra sesiones administrativas inactivas tras 5 minutos. | `line vty 0 4` / `transport input ssh` / `exec-timeout 5 0` |
| **CIS-IOS-1.2.5** | Protección contra ataques de fuerza bruta | Bloquea intentos de autenticación durante 120 segundos tras 3 fallos en un lapso de 60 segundos. | `login block-for 120 attempts 3 within 60` |
| **CIS-IOS-1.3.1** | Banner legal previo al inicio de sesión | Establece advertencia legal de acceso restringido antes de otorgar prompt administrativo. | `banner motd # ACCESO RESTRINGIDO - SOLO PERSONAL AUTORIZADO (20240886) #` |
| **CIS-IOS-2.1.1** | Deshabilitar servidores web HTTP/HTTPS locales | Reduce la superficie de ataque eliminando servicios de administración web innecesarios en el plano de control. | `no ip http server` / `no ip http secure-server` |
| **CIS-IOS-2.1.2** | Deshabilitar Cisco Discovery Protocol (CDP) | Impide la fuga de información de topología, versiones de IOS y direccionamiento a vecinos no confiables. | `no cdp run` |

#### Matriz CIS Benchmark para FortiOS (`FW-CIS-20240886`)

| ID Control CIS | Recomendación Técnica | Riesgo Mitigado y Justificación | Comandos Aplicados |
| :--- | :--- | :--- | :--- |
| **CIS-FGT-2.1.1** | Tiempo de inactividad administrativo $\le$ 5 min | Minimiza el riesgo de secuestro de sesión en consolas administrativas desatendidas. | `config system global` / `set admintimeout 5` |
| **CIS-FGT-2.1.2** | Criptografía fuerte TLS/SSH y deshabilitar SSHv1 | Fuerza el uso de suites de cifrado modernas y rechaza algoritmos débiles o vulnerables. | `set strong-crypto enable` / `set admin-ssh-v1 disable` |
| **CIS-FGT-2.1.4** | Habilitar banner de advertencia pre-login | Muestra aviso legal obligatorio antes de autenticar administradores en GUI y CLI. | `set pre-login-banner enable` |
| **CIS-FGT-2.2.1** | Eliminar protocolos en texto plano en interfaces | Suprime HTTP y Telnet de `port1`, permitiendo únicamente ICMP, HTTPS y SSHv2. | `config system interface` / `edit port1` / `set allowaccess ping https ssh` |

---

## 6. Políticas de Seguridad (Firewall Policies)

Para permitir la navegación de la red interna (`192.168.50.0/24`) hacia Internet a través del nodo `NAT1` manteniendo el aislamiento perimetral (bloqueo implícito de todo tráfico entrante no solicitado desde WAN hacia LAN), se implementó la siguiente política con traducción de direcciones origen (SNAT):

```fortios
config firewall policy
    edit 1
        set name "LAN-TO-WAN"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set nat enable
    next
end
```

| ID | Nombre | Origen (`srcintf`) | Destino (`dstintf`) | Dirección Origen/Destino | Servicio | Acción | NAT |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | `LAN-TO-WAN` | `port1` (Interna) | `port2` (Externa) | `all` $\rightarrow$ `all` | `ALL` | `ACCEPT` | Habilitado (SNAT) |
| **0** | `Implicit Deny` | `any` | `any` | `all` $\rightarrow$ `all` | `ALL` | `DENY` | Deshabilitado |

---

## 7. Validación y Pruebas Analíticas

### 7.1. Comparativa de Auditoría Automatizada (Antes vs. Después)

| Métrica Evaluada | Auditoría Inicial (`reporte_auditoria_inicial.txt`) | Auditoría Póstuma (`reporte_postumo_hardening.txt`) |
| :--- | :---: | :---: |
| **Controles Cisco IOS (`R1`)** | 1 / 7 Aprobados (14.3%) | **7 / 7 Aprobados (100.0%)** |
| **Controles Cisco IOS (`SW1`)** | 1 / 7 Aprobados (14.3%) | **7 / 7 Aprobados (100.0%)** |
| **Controles FortiOS (`FortiGate`)** | 0 / 4 Aprobados (0.0%) | **4 / 4 Aprobados (100.0%)** |
| **Cumplimiento Global** | **11.1% (2 / 18 Controles)** | **100.0% (18 / 18 Controles)** |

### 7.2. Matriz de Pruebas Funcionales y de Seguridad

| Prueba Ejecutada | Comando / Acción | Resultado Esperado | Estado |
| :--- | :--- | :--- | :---: |
| **Bloqueo de Telnet en R1/SW1** | `telnet 192.168.50.1` desde Ubuntu | Conexión rechazada (`Connection refused`). | **EXITOSO** |
| **Bloqueo de HTTP en FortiGate** | Acceso a `http://172.16.10.1` | Puerto 80 cerrado; solo responde HTTPS (443). | **EXITOSO** |
| **Acceso Administrativo SSHv2** | `ssh admin@192.168.50.1` / `172.16.10.1` | Despliegue del banner MOTD y sesión cifrada SSHv2. | **EXITOSO** |
| **Bloqueo por Fuerza Bruta** | 3 intentos fallidos de login en < 60s | Bloqueo temporal de nuevas sesiones por 120s. | **EXITOSO** |
| **Conectividad WAN e Internet** | `ping -c 3 8.8.8.8` y `ping google.com` | `0% packet loss` desde la estación Ubuntu (`192.168.50.10`). | **EXITOSO** |

---

## 8. Diagramas y Evidencias Visuales

*(Inserta en esta sección las capturas de pantalla obtenidas durante la práctica)*:

1. **Topología GNS3 con etiquetas de puertos activas:**  
  <img width="808" height="735" alt="imagen" src="https://github.com/user-attachments/assets/c5242453-2fd4-4945-8660-640b9545abdb" />

2. **Ejecución del script `cis_hardening_tool.py` (Auditoría Inicial vs. Remediación):**  
   INICIAL:
   <img width="915" height="538" alt="imagen" src="https://github.com/user-attachments/assets/5a04b7af-7a02-427b-a907-31ad00da5f31" />
   POSTUMO:
   <img width="919" height="454" alt="imagen" src="https://github.com/user-attachments/assets/af05a821-cd5b-4ccb-9aec-ed592b708ae0" />
   (los puse a mitad porque no cabe en el SC, archivos de las auditorias subidas al repositorio)
4. **Verificación de Banner MOTD y acceso SSHv2:**  
   FIREWALL:
   <img width="774" height="334" alt="imagen" src="https://github.com/user-attachments/assets/d9116251-902e-4684-806d-292b709f79cc" />
   R1:
   <img width="729" height="213" alt="imagen" src="https://github.com/user-attachments/assets/3be3f397-ea54-4af9-ac23-f6dd73fe734e" />

6. **Prueba de salida a Internet (`ping google.com`) tras aplicar hardening:**  
   <img width="904" height="294" alt="imagen" src="https://github.com/user-attachments/assets/1154b62f-9017-41e2-b862-89b26ff3fd76" />


---

## 9. Running Configurations Completas

TODO ESTO ESTA SUBIDO AL RESPOSITORIO

## 10. Scripts y Archivos Utilizados

### 10.1. Herramienta de Auditoría y Hardening (`cis_hardening_tool.py`)

```python
#!/usr/bin/env python3
import os
from datetime import datetime
from netmiko import ConnectHandler

# ==============================================================================
# INVENTARIO DE DISPOSITIVOS DE LA TOPOLOGÍA (MATRÍCULA: 20240886)
# ==============================================================================
DEVICES = {
    "R1": {
        "device_type": "cisco_ios",
        "host": "192.168.50.1",
        "username": "admin",
        "password": "cisco",
        "secret": "cisco",
        "use_keys": False,
        "allow_agent": False,
        "conn_timeout": 15,
    },
    "SW1": {
        "device_type": "cisco_ios",
        "host": "192.168.50.2",
        "username": "admin",
        "password": "cisco",
        "secret": "cisco",
        "use_keys": False,
        "allow_agent": False,
        "conn_timeout": 15,
    },
    "FortiGate": {
        "device_type": "fortinet",
        "host": "172.16.10.1",
        "username": "admin",
        "password": "cisco",
        "use_keys": False,
        "allow_agent": False,
        "conn_timeout": 20,
    },
}

# ==============================================================================
# REGLAS DE AUDITORÍA Y REMEDIACIÓN BASADAS EN CIS BENCHMARK
# ==============================================================================
CIS_CISCO_CHECKS = [
    {
        "id": "CIS-IOS-1.1.1",
        "desc": "Cifrado de contraseñas en texto plano (service password-encryption)",
        "pattern": "service password-encryption",
        "must_exist": True,
        "commands": ["service password-encryption"],
    },
    {
        "id": "CIS-IOS-1.2.1",
        "desc": "SSH Versión 2 obligatorio (ip ssh version 2)",
        "pattern": "ip ssh version 2",
        "must_exist": True,
        "commands": ["ip ssh version 2"],
    },
    {
        "id": "CIS-IOS-1.2.5",
        "desc": "Bloqueo ante fuerza bruta (login block-for 120 attempts 3 within 60)",
        "pattern": "login block-for 120 attempts 3 within 60",
        "must_exist": True,
        "commands": ["login block-for 120 attempts 3 within 60"],
    },
    {
        "id": "CIS-IOS-1.3.1",
        "desc": "Banner de advertencia legal (banner motd)",
        "pattern": "banner motd",
        "must_exist": True,
        "commands": ["banner motd # ACCESO RESTRINGIDO - SOLO PERSONAL AUTORIZADO (20240886) #"],
    },
    {
        "id": "CIS-IOS-2.1.1",
        "desc": "Deshabilitar servidor HTTP inseguro (no ip http server)",
        "pattern": "no ip http server",
        "must_exist": True,
        "commands": ["no ip http server", "no ip http secure-server"],
    },
    {
        "id": "CIS-IOS-2.1.2",
        "desc": "Deshabilitar protocolo de descubrimiento CDP (no cdp run)",
        "pattern": "no cdp run",
        "must_exist": True,
        "commands": ["no cdp run"],
    },
    {
        "id": "CIS-IOS-1.2.3",
        "desc": "Transporte exclusivo SSH y timeout de 5 min en líneas VTY",
        "pattern": "transport input ssh",
        "must_exist": True,
        "commands": [
            "line vty 0 4",
            "transport input ssh",
            "exec-timeout 5 0",
            "line con 0",
            "exec-timeout 5 0",
            "exit",
        ],
    },
]

CIS_FORTI_CHECKS = [
    {
        "id": "CIS-FGT-2.1.1",
        "desc": "Tiempo de inactividad administrativo <= 5 min (admintimeout 5)",
        "pattern": "set admintimeout 5",
        "must_exist": True,
        "commands": [
            "config system global",
            "set admintimeout 5",
            "end",
        ],
    },
    {
        "id": "CIS-FGT-2.1.2",
        "desc": "Criptografía fuerte TLS/SSH habilitada (strong-crypto enable)",
        "pattern": "set strong-crypto enable",
        "must_exist": True,
        "commands": [
            "config system global",
            "set strong-crypto enable",
            "set admin-ssh-v1 disable",
            "end",
        ],
    },
    {
        "id": "CIS-FGT-2.1.4",
        "desc": "Banner de advertencia previo al inicio de sesión (pre-login-banner)",
        "pattern": "set pre-login-banner enable",
        "must_exist": True,
        "commands": [
            "config system global",
            "set pre-login-banner enable",
            "end",
        ],
    },
    {
        "id": "CIS-FGT-2.2.1",
        "desc": "Eliminar gestión administrativa en texto plano (HTTP/Telnet en port1)",
        "pattern": "set allowaccess ping https ssh",
        "must_exist": True,
        "commands": [
            "config system interface",
            "edit port1",
            "set allowaccess ping https ssh",
            "next",
            "end",
        ],
    },
]


def audit_cisco(conn, dev_name):
    running_cfg = conn.send_command("show running-config")
    results = []
    for rule in CIS_CISCO_CHECKS:
        passed = (rule["pattern"] in running_cfg) == rule["must_exist"]
        results.append({
            "device": dev_name,
            "id": rule["id"],
            "desc": rule["desc"],
            "status": "CUMPLE" if passed else "NO CUMPLE",
            "commands": rule["commands"],
        })
    return results


def audit_fortigate(conn, dev_name):
    global_cfg = conn.send_command("show system global")
    intf_cfg = conn.send_command("show system interface port1")
    full_cfg = f"{global_cfg}\n{intf_cfg}"
    results = []
    for rule in CIS_FORTI_CHECKS:
        passed = (rule["pattern"] in full_cfg) == rule["must_exist"]
        results.append({
            "device": dev_name,
            "id": rule["id"],
            "desc": rule["desc"],
            "status": "CUMPLE" if passed else "NO CUMPLE",
            "commands": rule["commands"],
        })
    return results


def run_assessment(apply_fixes=False):
    all_results = []
    applied_log = []

    for dev_name, dev_params in DEVICES.items():
        print(f"\n[*] Conectando a {dev_name} ({dev_params['host']})...")
        try:
            conn = ConnectHandler(**dev_params)
            if dev_params["device_type"] == "cisco_ios":
                conn.enable()
                results = audit_cisco(conn, dev_name)
                if apply_fixes:
                    cmds_to_push = []
                    for r in results:
                        if r["status"] == "NO CUMPLE":
                            cmds_to_push.extend(r["commands"])
                            applied_log.append(f"[{dev_name}] Aplicada regla {r['id']}: {r['desc']}")
                    if cmds_to_push:
                        print(f"[+] Aplicando {len(cmds_to_push)} comandos CIS en {dev_name}...")
                        conn.send_config_set(cmds_to_push)
                        conn.save_config()
                    results = audit_cisco(conn, dev_name)

            elif dev_params["device_type"] == "fortinet":
                results = audit_fortigate(conn, dev_name)
                if apply_fixes:
                    cmds_to_push = []
                    for r in results:
                        if r["status"] == "NO CUMPLE":
                            cmds_to_push.extend(r["commands"])
                            applied_log.append(f"[{dev_name}] Aplicada regla {r['id']}: {r['desc']}")
                    if cmds_to_push:
                        print(f"[+] Aplicando hardening CIS en {dev_name}...")
                        conn.send_config_set(cmds_to_push, exit_config_mode=False)
                    results = audit_fortigate(conn, dev_name)

            conn.disconnect()
            all_results.extend(results)
            print(f"[OK] Evaluación completada en {dev_name}.")

        except Exception as e:
            print(f"[ERROR] No se pudo conectar a {dev_name}: {e}")
            all_results.append({
                "device": dev_name,
                "id": "CONN-ERR",
                "desc": f"Error de conexión SSH: {e}",
                "status": "ERROR",
                "commands": [],
            })

    return all_results, applied_log


def generate_report(results, applied_log, mode_label, filename):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len([r for r in results if r["status"] != "ERROR"])
    passed = len([r for r in results if r["status"] == "CUMPLE"])
    failed = len([r for r in results if r["status"] == "NO CUMPLE"])
    score = (passed / total * 100) if total > 0 else 0

    lines = [
        "=" * 78,
        f"INFORME DE CUMPLIMIENTO CIS BENCHMARK - {mode_label}",
        f"Fecha y Hora: {now} | Estación Auditora: 192.168.50.10",
        "=" * 78,
        f"RESUMEN EJECUTIVO: {passed}/{total} Controles Aprobados ({score:.1f}% de Cumplimiento)",
        f"Controles Fallidos Pendientes: {failed}",
        "-" * 78,
    ]

    if applied_log:
        lines.append("ACCIONES DE REMEDIACIÓN EJECUTADAS:")
        for entry in applied_log:
            lines.append(f"  * {entry}")
        lines.append("-" * 78)

    lines.append(f"{'DISPOSITIVO':<12} | {'ID CONTROL':<14} | {'ESTADO':<10} | {'DESCRIPCIÓN'}")
    lines.append("-" * 78)
    for r in results:
        lines.append(f"{r['device']:<12} | {r['id']:<14} | {r['status']:<10} | {r['desc']}")
    lines.append("=" * 78)

    report_text = "\n".join(lines)
    print("\n" + report_text)

    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_text + "\n")
    print(f"\n[ARCHIVO GUARDADO] Informe exportado en: {os.path.abspath(filename)}")


def main():
    while True:
        print("\n" + "=" * 60)
        print("  HERRAMIENTA AUTOMATIZADA DE HARDENING CIS (NETMIKO)")
        print("=" * 60)
        print("  1. Modo Auditoría (Solo análisis en vivo, sin aplicar cambios)")
        print("  2. Modo Remediación (Aplicar hardening CIS + Informe póstumo)")
        print("  3. Salir")
        print("=" * 60)
        choice = input("Selecciona una opción [1-3]: ").strip()

        if choice == "1":
            results, applied_log = run_assessment(apply_fixes=False)
            generate_report(
                results,
                applied_log,
                "AUDITORÍA INICIAL (DRY-RUN)",
                "reporte_auditoria_inicial.txt",
            )
        elif choice == "2":
            confirm = input("¿Confirmas aplicar las reglas CIS en R1, SW1 y FortiGate? (s/n): ").strip().lower()
            if confirm == "s":
                results, applied_log = run_assessment(apply_fixes=True)
                generate_report(
                    results,
                    applied_log,
                    "AUDITORÍA PÓSTUMA POST-HARDENING",
                    "reporte_postumo_hardening.txt",
                )
            else:
                print("[!] Operación cancelada.")
        elif choice == "3":
            print("Saliendo de la herramienta...")
            break
        else:
            print("[!] Opción no válida. Intenta de nuevo.")


if __name__ == "__main__":
    main()
```

### 10.2. Reportes Generados (`reporte_auditoria_inicial.txt` y `reporte_postumo_hardening.txt`)

ESTA PEGADO AL REPOSITORIO

## 11. Conclusión

La integración de marcos de referencia como los **CIS Benchmarks** junto con herramientas de automatización basadas en **Python y Netmiko** demuestra ser un enfoque altamente eficaz para elevar la postura de seguridad en infraestructuras de red multi-fabricante.

A través de este laboratorio se comprobó que:
1. La auditoría automatizada permite detectar de forma inmediata brechas críticas de configuración que suelen pasar desapercibidas en despliegues manuales (como protocolos en texto plano habilitados por defecto o ausencia de protección contra fuerza bruta).
2. El endurecimiento programático garantiza consistencia entre dispositivos **Cisco IOS** y **Fortinet FortiOS**, reduciendo tiempos de despliegue y eliminando errores de sintaxis.
3. La validación póstuma confirma que es posible alcanzar el **100% de cumplimiento normativo** en el plano de control y gestión sin degradar la disponibilidad del servicio ni el tráfico legítimo hacia Internet.
