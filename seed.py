"""
Carga inicial de datos (seed) para CyberRisk 360.

Crea:
  - Usuarios de demostración (administrador y analista).
  - Catálogo de controles ISO/IEC 27002:2022 (selección representativa).
  - Catálogos de amenazas y vulnerabilidades (ISO/IEC 27005).
  - Un caso de estudio: la empresa ficticia "FinTech Andina S.A." con activos,
    riesgos y tratamientos ya valorados, para poder demostrar el sistema.

Uso:
    python seed.py
"""
from datetime import date, datetime, timedelta

from app.extensions import db
from app.models import (
    User, Asset, Threat, Vulnerability, Risk, Control, Treatment, Observation,
    Setting, AuditLog, RiskSnapshot, cyber_exposure_score
)

_app_instance = None
_seeding = False


def _get_app():
    global _app_instance
    if _app_instance is None:
        from app import create_app
        _app_instance = create_app()
    return _app_instance


# --- Selección representativa de controles ISO/IEC 27002:2022 (93 controles,
#     4 temas). Se incluye una muestra de cada tema para el tratamiento. ---
# (código ISO, nombre, tema ISO 27002:2022, función NIST CSF 2.0)
CONTROLES_ISO = [
    # Organizacionales (5.x)
    ("5.1", "Políticas de seguridad de la información", "Organizacional", "Govern"),
    ("5.7", "Inteligencia de amenazas", "Organizacional", "Identify"),
    ("5.10", "Uso aceptable de la información y activos", "Organizacional", "Protect"),
    ("5.12", "Clasificación de la información", "Organizacional", "Identify"),
    ("5.15", "Control de acceso", "Organizacional", "Protect"),
    ("5.23", "Seguridad para uso de servicios en la nube", "Organizacional", "Protect"),
    ("5.24", "Planificación y preparación de gestión de incidentes", "Organizacional", "Respond"),
    ("5.30", "Preparación de las TIC para la continuidad del negocio", "Organizacional", "Recover"),
    # Personas (6.x)
    ("6.3", "Concienciación, educación y capacitación", "Personas", "Protect"),
    ("6.5", "Responsabilidades tras el cese o cambio de empleo", "Personas", "Protect"),
    ("6.7", "Trabajo remoto", "Personas", "Protect"),
    ("6.8", "Reporte de eventos de seguridad de la información", "Personas", "Detect"),
    # Físicos (7.x)
    ("7.2", "Controles de acceso físico", "Físico", "Protect"),
    ("7.4", "Monitoreo de seguridad física", "Físico", "Detect"),
    ("7.10", "Medios de almacenamiento", "Físico", "Protect"),
    # Tecnológicos (8.x)
    ("8.1", "Dispositivos endpoint de usuario", "Tecnológico", "Protect"),
    ("8.2", "Derechos de acceso privilegiado", "Tecnológico", "Protect"),
    ("8.3", "Restricción de acceso a la información", "Tecnológico", "Protect"),
    ("8.5", "Autenticación segura (MFA)", "Tecnológico", "Protect"),
    ("8.7", "Protección contra malware", "Tecnológico", "Protect"),
    ("8.8", "Gestión de vulnerabilidades técnicas", "Tecnológico", "Identify"),
    ("8.9", "Gestión de la configuración", "Tecnológico", "Protect"),
    ("8.12", "Prevención de fuga de datos (DLP)", "Tecnológico", "Protect"),
    ("8.13", "Respaldo de la información (Backup)", "Tecnológico", "Recover"),
    ("8.15", "Registro de eventos (Logging)", "Tecnológico", "Detect"),
    ("8.16", "Monitoreo de actividades", "Tecnológico", "Detect"),
    ("8.20", "Seguridad de redes", "Tecnológico", "Protect"),
    ("8.23", "Filtrado web", "Tecnológico", "Protect"),
    ("8.24", "Uso de criptografía", "Tecnológico", "Protect"),
    ("8.25", "Ciclo de vida de desarrollo seguro", "Tecnológico", "Protect"),
    ("8.28", "Codificación segura", "Tecnológico", "Protect"),
]

# (nombre, categoría, descripción, MITRE ATT&CK ID, táctica ATT&CK)
AMENAZAS = [
    ("Ransomware", "Malware", "Cifrado malicioso de datos con extorsión económica.", "T1486", "Impact"),
    ("Phishing / Ingeniería social", "Ingeniería social", "Engaño para obtener credenciales o datos.", "T1566", "Initial Access"),
    ("Acceso no autorizado", "Acceso", "Terceros acceden a sistemas sin permiso.", "T1078", "Initial Access"),
    ("Fuga de información", "Divulgación", "Exfiltración de datos confidenciales.", "T1567", "Exfiltration"),
    ("Denegación de servicio (DDoS)", "Disponibilidad", "Saturación que interrumpe el servicio.", "T1498", "Impact"),
    ("Error humano", "Error humano", "Acciones involuntarias que causan incidentes.", "T1204", "Execution"),
    ("Inyección SQL", "Ataque web", "Manipulación de consultas a base de datos.", "T1190", "Initial Access"),
    ("Fallo de hardware", "Físico", "Avería de equipos que afecta la disponibilidad.", None, None),
    ("Amenaza interna (insider)", "Interno", "Personal que abusa de sus privilegios.", "T1078.004", "Privilege Escalation"),
    ("Robo/pérdida de dispositivo", "Físico", "Extravío de equipos con información.", "T1200", "Initial Access"),
]

VULNERABILIDADES = [
    ("Ausencia de MFA", "Autenticación", "Solo contraseña para acceder a sistemas críticos."),
    ("Software sin parches", "Gestión de parches", "Sistemas con vulnerabilidades conocidas sin corregir."),
    ("Contraseñas débiles", "Autenticación", "Políticas de contraseña insuficientes."),
    ("Falta de cifrado", "Criptografía", "Datos sensibles almacenados/transmitidos en claro."),
    ("Sin respaldos verificados", "Continuidad", "Backups inexistentes o no probados."),
    ("Personal sin capacitación", "Concienciación", "Usuarios susceptibles a ingeniería social."),
    ("Validación de entrada deficiente", "Desarrollo", "Aplicaciones sin sanitización de datos."),
    ("Reglas de firewall permisivas", "Red", "Segmentación de red inadecuada."),
    ("Privilegios excesivos", "Control de acceso", "Usuarios con más permisos de los necesarios."),
    ("Logs no monitoreados", "Monitoreo", "Eventos de seguridad sin revisión."),
]


def seed():
    global _seeding
    if _seeding:
        return
    _seeding = True
    app = _get_app()
    with app.app_context():
        db.drop_all()
        db.create_all()

        # --- Usuarios ---
        admin = User(nombre="Administrador GRC", email="admin@cyberrisk360.com", rol="administrador")
        admin.set_password("Admin123")
        analista = User(nombre="Analista de Riesgos", email="analista@cyberrisk360.com", rol="analista")
        analista.set_password("Analista123")
        db.session.add_all([admin, analista])

        # --- Controles ISO 27002:2022 ---
        controles = {}
        for codigo, nombre, tema, nist in CONTROLES_ISO:
            c = Control(codigo_iso=codigo, nombre=nombre, tema=tema, nist_csf=nist)
            db.session.add(c)
            controles[codigo] = c

        # --- Amenazas y vulnerabilidades ---
        amenazas = {}
        for nombre, cat, desc, aid, atac in AMENAZAS:
            t = Threat(nombre=nombre, categoria=cat, descripcion=desc,
                       attack_id=aid, attack_tactica=atac)
            db.session.add(t)
            amenazas[nombre] = t

        vulns = {}
        for nombre, cat, desc in VULNERABILIDADES:
            v = Vulnerability(nombre=nombre, categoria=cat, descripcion=desc)
            db.session.add(v)
            vulns[nombre] = v

        # Vulnerabilidades vinculadas a CVE reales, con inteligencia de amenazas
        # pre-cargada (valores reales de NVD/EPSS/CISA KEV) para que la demo
        # muestre el módulo de CTI aunque no haya conexión. El botón "Enriquecer"
        # consulta las APIs en vivo para actualizarlas o agregar nuevas.
        from datetime import datetime as _dt
        VULNS_CVE = [
            {"nombre": "Log4Shell (Apache Log4j2 RCE)", "categoria": "Desarrollo",
             "descripcion": "Ejecución remota de código vía JNDI en Log4j2.",
             "cve_id": "CVE-2021-44228", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
             "cvss_score": 10.0, "epss_score": 0.99999, "epss_percentile": 1.0, "kev": True, "kev_fecha": "2021-12-10"},
            {"nombre": "EternalBlue (SMBv1 RCE)", "categoria": "Red",
             "descripcion": "Ejecución remota de código en el servidor SMBv1 de Windows.",
             "cve_id": "CVE-2017-0144", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
             "cvss_score": 8.8, "epss_score": 0.9923, "epss_percentile": 0.99931, "kev": True, "kev_fecha": "2022-02-10"},
        ]
        for d in VULNS_CVE:
            v = Vulnerability(intel_fecha=_dt.utcnow(), **d)
            db.session.add(v)
            vulns[d["nombre"]] = v

        db.session.commit()

        # --- Caso de estudio: FinTech Andina S.A. ---
        activos_data = [
            ("ACT-001", "Base de datos de clientes", "Datos personales y financieros de clientes.", "Información", "Jefe de Datos", 5, 5, 4),
            ("ACT-002", "Aplicación web de banca en línea", "Portal transaccional de clientes.", "Software", "Líder de Desarrollo", 4, 5, 5),
            ("ACT-003", "Servidor de correo corporativo", "Comunicaciones internas y externas.", "Servicio", "Administrador de TI", 4, 4, 4),
            ("ACT-004", "Repositorio de código fuente", "Código de las aplicaciones propias.", "Información", "Líder de Desarrollo", 4, 4, 3),
            ("ACT-005", "Estaciones de trabajo del personal", "Equipos de los colaboradores.", "Hardware", "Soporte TI", 3, 3, 3),
            ("ACT-006", "Servidor de respaldos", "Copias de seguridad de sistemas.", "Hardware", "Administrador de TI", 4, 5, 4),
        ]
        activos = {}
        for codigo, nombre, desc, tipo, prop, c, i, d in activos_data:
            a = Asset(codigo=codigo, nombre=nombre, descripcion=desc, tipo=tipo,
                      propietario=prop, confidencialidad=c, integridad=i, disponibilidad=d)
            db.session.add(a)
            activos[codigo] = a
        db.session.commit()

        # --- Riesgos (Activo + Amenaza + Vulnerabilidad, P x I) ---
        riesgos_data = [
            # codigo, activo, amenaza, vuln, prob, imp, controles_existentes, estado
            ("R-001", "ACT-001", "Fuga de información", "Falta de cifrado", 4, 5, "Control de acceso por roles.", "En Tratamiento"),
            ("R-002", "ACT-002", "Inyección SQL", "Validación de entrada deficiente", 4, 5, "Firewall de aplicaciones básico.", "En Tratamiento"),
            ("R-003", "ACT-001", "Ransomware", "Software sin parches", 4, 5, "Antivirus tradicional.", "En Tratamiento"),
            ("R-004", "ACT-003", "Phishing / Ingeniería social", "Personal sin capacitación", 5, 4, "Filtro antispam.", "En Tratamiento"),
            ("R-005", "ACT-002", "Acceso no autorizado", "Ausencia de MFA", 4, 4, "Usuario y contraseña.", "En Tratamiento"),
            ("R-006", "ACT-006", "Fallo de hardware", "Sin respaldos verificados", 3, 5, "Respaldo manual esporádico.", "Identificado"),
            ("R-007", "ACT-004", "Amenaza interna (insider)", "Privilegios excesivos", 3, 4, "Repositorio privado.", "Identificado"),
            ("R-008", "ACT-005", "Robo/pérdida de dispositivo", "Falta de cifrado", 3, 3, "Ninguno.", "Identificado"),
            ("R-009", "ACT-002", "Denegación de servicio (DDoS)", "Reglas de firewall permisivas", 3, 4, "Firewall perimetral.", "Identificado"),
            ("R-010", "ACT-003", "Acceso no autorizado", "Logs no monitoreados", 3, 3, "Logs habilitados sin revisión.", "Identificado"),
            # Riesgos vinculados a CVE reales (con inteligencia de amenazas).
            ("R-011", "ACT-002", "Acceso no autorizado", "Log4Shell (Apache Log4j2 RCE)", 4, 5, "WAF con reglas genéricas.", "Identificado"),
            ("R-012", "ACT-003", "Ransomware", "EternalBlue (SMBv1 RCE)", 3, 5, "SMBv1 deshabilitado parcialmente.", "En Tratamiento"),
        ]
        riesgos = {}
        for codigo, act, ame, vul, p, i, ce, estado in riesgos_data:
            r = Risk(codigo=codigo, asset_id=activos[act].id, threat_id=amenazas[ame].id,
                     vulnerability_id=vulns[vul].id, probabilidad=p, impacto=i,
                     controles_existentes=ce, estado=estado,
                     descripcion=f"Riesgo de {ame.lower()} sobre {activos[act].nombre.lower()}.")
            db.session.add(r)
            riesgos[codigo] = r
        db.session.commit()

        # Envejecimiento de fechas para demostrar el control de SLA de
        # remediación (riesgos abiertos que ya superaron su ventana de tratamiento).
        edades = {"R-004": 20, "R-006": 45, "R-007": 40, "R-009": 38, "R-011": 50, "R-012": 25}
        for cod, dias in edades.items():
            riesgos[cod].creado_en = datetime.utcnow() - timedelta(days=dias)
        db.session.commit()

        # --- Tratamientos (estrategia + control ISO + eficacia) ---
        hoy = date.today()
        tratamientos_data = [
            # riesgo, estrategia, control_iso, desc, responsable, eficacia, estado
            ("R-001", "Mitigar", "8.24", "Implementar cifrado AES-256 en reposo y TLS en tránsito.", "Administrador de TI", 70, "Implementado"),
            ("R-001", "Mitigar", "8.12", "Desplegar solución DLP para datos de clientes.", "Oficial de Seguridad", 40, "En Implementación"),
            ("R-002", "Mitigar", "8.28", "Aplicar codificación segura y consultas parametrizadas.", "Líder de Desarrollo", 75, "Implementado"),
            ("R-002", "Mitigar", "8.8", "Análisis de vulnerabilidades y pruebas de penetración.", "Oficial de Seguridad", 50, "En Implementación"),
            ("R-003", "Mitigar", "8.7", "Desplegar EDR con protección anti-ransomware.", "Administrador de TI", 65, "Implementado"),
            ("R-003", "Mitigar", "8.13", "Backups 3-2-1 con pruebas de restauración.", "Administrador de TI", 60, "Implementado"),
            ("R-004", "Mitigar", "6.3", "Programa de concienciación y simulacros de phishing.", "Recursos Humanos", 55, "En Implementación"),
            ("R-005", "Mitigar", "8.5", "Habilitar autenticación multifactor (MFA).", "Administrador de TI", 80, "Implementado"),
            ("R-006", "Mitigar", "8.13", "Política de respaldos automatizados y verificados.", "Administrador de TI", 70, "Propuesto"),
            ("R-006", "Transferir", None, "Contratar seguro de continuidad / servicio en nube.", "Gerencia", 30, "Propuesto"),
            ("R-007", "Mitigar", "8.2", "Aplicar mínimo privilegio y revisión de accesos.", "Oficial de Seguridad", 60, "Propuesto"),
            ("R-008", "Mitigar", "8.1", "Cifrado de disco completo en endpoints.", "Soporte TI", 65, "Propuesto"),
            ("R-009", "Mitigar", "8.20", "Segmentación de red y anti-DDoS en el CDN.", "Administrador de TI", 55, "Propuesto"),
            ("R-010", "Mitigar", "8.16", "Implementar SIEM con monitoreo 24/7.", "Oficial de Seguridad", 60, "Propuesto"),
        ]
        for codigo, estr, ctrl_iso, desc, resp, efi, estado in tratamientos_data:
            t = Treatment(
                risk_id=riesgos[codigo].id,
                control_id=controles[ctrl_iso].id if ctrl_iso else None,
                estrategia=estr, descripcion=desc, responsable=resp,
                eficacia=efi, estado=estado,
                fecha_objetivo=hoy + timedelta(days=45),
            )
            db.session.add(t)

        # --- Observaciones / recomendaciones (Fase 5) ---
        observaciones = [
            (None, "Recomendación", "Oficial de Seguridad", "Se recomienda priorizar la implementación de MFA y cifrado por su alto impacto en riesgos críticos."),
            ("R-003", "Observación", "Administrador de TI", "El EDR ya redujo significativamente la exposición a ransomware; falta verificar restauración de backups."),
            (None, "Recomendación", "Gerencia", "Aprobar presupuesto para el SIEM permitiría cerrar el riesgo R-010 de monitoreo."),
        ]
        for codigo, tipo, autor, contenido in observaciones:
            obs = Observation(
                risk_id=riesgos[codigo].id if codigo else None,
                tipo=tipo, autor=autor, contenido=contenido,
            )
            db.session.add(obs)

        # --- Historial de 12 semanas (tendencia de la postura de riesgo) ---
        # Simula la mejora progresiva conforme se implementan controles: el CES
        # y los riesgos críticos descienden mientras crecen los controles.
        from app.models import RiskSnapshot
        ces_actual = cyber_exposure_score(list(riesgos.values()))
        for semana in range(12, -1, -1):
            # hace 12 semanas la exposición era mayor y había menos controles
            factor = 1 + semana * 0.055
            ces_hist = min(1000, round(ces_actual * factor))
            db.session.add(RiskSnapshot(
                fecha=date.today() - timedelta(weeks=semana),
                ces=ces_hist,
                riesgo_residual_total=round(sum(r.puntaje_residual for r in riesgos.values()) * factor),
                n_criticos=min(12, 4 + semana),
                n_controles=max(0, 8 - semana // 2),
            ))

        # --- Configuración organizacional (apetito de riesgo) ---
        db.session.add(Setting(id=1, organizacion="FinTech Andina S.A.", apetito_riesgo=9))

        # --- Bitácora de auditoría inicial ---
        db.session.add(AuditLog(usuario="Administrador GRC", accion="CREAR", entidad="Sistema",
                                detalle="Inicialización del sistema con el caso FinTech Andina S.A."))

        db.session.commit()
        print("=" * 60)
        print(" Base de datos inicializada con el caso 'FinTech Andina S.A.'")
        print("=" * 60)
        print(f"  Controles ISO 27002:2022 : {len(CONTROLES_ISO)}")
        print(f"  Amenazas                 : {len(AMENAZAS)}")
        print(f"  Vulnerabilidades         : {len(VULNERABILIDADES)}")
        print(f"  Activos                  : {len(activos_data)}")
        print(f"  Riesgos                  : {len(riesgos_data)}")
        print(f"  Tratamientos             : {len(tratamientos_data)}")
        print("-" * 60)
        print("  Credenciales de acceso:")
        print("   Admin    -> admin@cyberrisk360.com    / Admin123")
        print("   Analista -> analista@cyberrisk360.com / Analista123")
        print("=" * 60)


if __name__ == "__main__":
    seed()
    # Mostrar credenciales
    app = _get_app()
    with app.app_context():
        print("  Credenciales de acceso:")
        print("   Admin    -> admin@cyberrisk360.com    / Admin123")
        print("   Analista -> analista@cyberrisk360.com / Analista123")
