/**
 * Cliente tipado de la API REST de CyberRisk 360 (backend Flask).
 *
 * En SSR las páginas Astro llaman a estas funciones en el servidor; en el
 * cliente, las islas interactivas usan `API_URL` para POST (enriquecer, crear).
 */

export const API_URL: string =
  (import.meta.env.PUBLIC_API_URL as string) || 'http://127.0.0.1:5000/api';

// --------------------------- Tipos del dominio ---------------------------

export interface Nivel { nombre: string; clase: string; color: string; }

export interface Vulnerabilidad {
  id: number; nombre: string; categoria: string | null; descripcion: string | null;
  cve_id: string | null; cvss_score: number | null; cvss_vector: string | null;
  cvss_severidad: string | null; epss_pct: number | null; epss_percentile: number | null;
  kev: boolean; kev_fecha: string | null; vpr: number | null; vpr_nivel: string | null;
  intel_fecha: string | null;
}

export interface Amenaza {
  id: number; nombre: string; categoria: string | null; descripcion: string | null;
  attack_id: string | null; attack_tactica: string | null;
}

export interface Activo {
  id: number; codigo: string; nombre: string; descripcion: string | null; tipo: string;
  propietario: string | null; confidencialidad: number; integridad: number;
  disponibilidad: number; valor: number; valor_texto: string; n_riesgos: number;
}

export interface Control {
  codigo_iso: string; nombre: string; tema: string; nist_csf: string | null;
}

export interface Tratamiento {
  id: number; estrategia: string; descripcion: string | null; responsable: string | null;
  eficacia: number; estado: string; fecha_objetivo: string | null; control: Control | null;
}

export interface Observacion {
  id: number; tipo: string; autor: string; contenido: string;
  risk_id: number | null; risk_codigo: string | null; creado_en: string;
}

export interface Riesgo {
  id: number; codigo: string; descripcion: string | null; estado: string;
  activo: { id: number; codigo: string; nombre: string; valor: number };
  amenaza: Amenaza; vulnerabilidad: Vulnerabilidad;
  probabilidad: number; impacto: number;
  puntaje_inherente: number; nivel_inherente: Nivel;
  puntaje_residual: number; nivel_residual: Nivel;
  reduccion_pct: number; eficacia_total: number;
  sla_dias: number; sla_restante: number; sla_vencido: boolean;
  controles_existentes?: string | null;
  tratamientos?: Tratamiento[];
  observaciones?: Observacion[];
}

export interface Overview {
  organizacion: string; apetito_riesgo: number;
  kpis: { activos: number; riesgos: number; controles: number; reduccion: number };
  ces: { score: number; nivel: string; clase: string };
  matriz: number[][];
  dist_inherente: Record<string, number>;
  dist_residual: Record<string, number>;
  estados_control: Record<string, number>;
  sobre_apetito: Riesgo[]; sla_vencidos: Riesgo[]; criticos: Riesgo[];
  historial: { fechas: string[]; ces: number[]; criticos: number[] };
  observaciones: Observacion[];
}

export interface IntelData {
  kpis: { enriquecidas: number; total: number; kev: number; vpr_critico: number; epss_alto: number };
  vulnerabilidades: Vulnerabilidad[];
}

export interface ComplianceData {
  cobertura_iso: number; total_catalogo: number; aplicados: number;
  temas: Record<string, { total: number; aplicados: number }>;
  nist: { clave: string; nombre: string; desc: string; catalogo: number; aplicados: number; pct: number }[];
}

export interface AuditEntry {
  usuario: string; accion: string; entidad: string; detalle: string; creado_en: string;
}

export interface Catalogs {
  activos: Activo[]; amenazas: Amenaza[]; vulnerabilidades: Vulnerabilidad[];
  estados_riesgo: string[]; estrategias: string[]; estados_control: string[];
}

// --------------------------- Funciones de acceso ---------------------------

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, { headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`API ${path} -> ${res.status}`);
  return res.json() as Promise<T>;
}

export const getOverview = () => get<Overview>('/overview');
export const getRisks = () => get<Riesgo[]>('/risks');
export const getRisk = (id: number | string) => get<Riesgo>(`/risks/${id}`);
export const getAssets = () => get<Activo[]>('/assets');
export const getIntel = () => get<IntelData>('/intel');
export const getCompliance = () => get<ComplianceData>('/compliance');
export const getAudit = () => get<AuditEntry[]>('/audit');
export const getCatalogs = () => get<Catalogs>('/catalogs');

/** Paleta compartida: severidad ordinal + categórica validada (dataviz). */
export const PALETA = {
  sev: { Bajo: '#2e9e5b', Medio: '#e0a800', Alto: '#e8590c', 'Crítico': '#d63a3a' } as Record<string, string>,
  cat: ['#4c82f7', '#14a89a', '#8b5cf6', '#d97706'],
  brand: '#4c82f7', teal: '#34d3c0',
};

/** Devuelve la clase de chip según el nombre de nivel. */
export function chipClass(nivel: string): string {
  const n = nivel.toLowerCase();
  if (n === 'crítico' || n === 'crítica') return 'critico';
  if (n === 'alto' || n === 'alta') return 'alto';
  if (n === 'medio' || n === 'media') return 'medio';
  return 'bajo';
}
