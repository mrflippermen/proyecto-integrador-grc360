/* CyberRisk 360 — App cliente (una sola página, sin backend).
   Toda la lógica de la metodología GRC-360 vive aquí y persiste en localStorage. */
(function () {
'use strict';

// ===================== Datos de inteligencia embebidos =====================
// Como el Artifact no puede llamar APIs externas, se incluye un pequeño
// catálogo real de CVE frecuentes para demostrar el enriquecimiento. La
// versión completa (Flask) consulta NVD, EPSS y CISA KEV en vivo.
var CVE_DB = {
  'CVE-2021-44228': { cvss:10.0, vec:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', epss:0.99999, kev:true, kevf:'2021-12-10', desc:'Apache Log4j2 — ejecución remota de código (Log4Shell) vía JNDI.' },
  'CVE-2017-0144': { cvss:8.8, vec:'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', epss:0.9923, kev:true, kevf:'2022-02-10', desc:'SMBv1 de Windows — ejecución remota de código (EternalBlue).' },
  'CVE-2014-0160': { cvss:7.5, vec:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', epss:0.99998, kev:true, kevf:'2022-05-04', desc:'OpenSSL Heartbleed — fuga de memoria del proceso (claves privadas).' },
  'CVE-2019-0708': { cvss:9.8, vec:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', epss:0.9721, kev:true, kevf:'2021-11-03', desc:'RDP de Windows — ejecución remota de código (BlueKeep).' },
  'CVE-2021-34527': { cvss:8.8, vec:'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', epss:0.9459, kev:true, kevf:'2021-07-13', desc:'Windows Print Spooler — ejecución remota (PrintNightmare).' },
  'CVE-2022-1388': { cvss:9.8, vec:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', epss:0.9740, kev:true, kevf:'2022-05-18', desc:'F5 BIG-IP iControl REST — bypass de autenticación y RCE.' },
  'CVE-2023-34362': { cvss:9.8, vec:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', epss:0.9410, kev:true, kevf:'2023-06-02', desc:'MOVEit Transfer — inyección SQL con exfiltración masiva de datos.' },
  'CVE-2020-1472': { cvss:10.0, vec:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', epss:0.9738, kev:true, kevf:'2021-11-03', desc:'Netlogon de Windows — elevación de privilegios (Zerologon).' }
};

// ===================== Semilla y estado =====================
var STORE_KEY = 'cyberrisk360.state.v1';
var state, uid;

function freshFromSeed(){ return JSON.parse(JSON.stringify(window.SEED)); }
function loadState(){
  try { var s = localStorage.getItem(STORE_KEY); state = s ? JSON.parse(s) : freshFromSeed(); }
  catch(e){ state = freshFromSeed(); }
  // id incremental sobre el máximo existente
  var ids = [].concat(state.activos, state.amenazas, state.vulnerabilidades, state.riesgos).map(function(x){return x.id||0;});
  uid = Math.max.apply(null, ids.concat([0])) + 1;
}
function saveState(){ try{ localStorage.setItem(STORE_KEY, JSON.stringify(state)); }catch(e){} }
function resetDemo(){ if(confirm('¿Restablecer los datos de ejemplo? Se perderán los cambios locales.')){ localStorage.removeItem(STORE_KEY); loadState(); toast('Datos de ejemplo restablecidos.','ok'); go(current); } }
function nextId(){ return uid++; }

// ===================== Utilidades de la metodología =====================
var ESCALA = {1:'Muy Bajo',2:'Bajo',3:'Medio',4:'Alto',5:'Muy Alto'};
var SLA_DIAS = {'Crítico':15,'Alto':30,'Medio':60,'Bajo':90};
function nivel(p){
  if(p<=4) return {n:'Bajo',c:'bajo',col:'#2e9e5b'};
  if(p<=9) return {n:'Medio',c:'medio',col:'#e0a800'};
  if(p<=14) return {n:'Alto',c:'alto',col:'#e8590c'};
  return {n:'Crítico',c:'critico',col:'#d63a3a'};
}
var A={},T={},V={},C={};
function reindex(){ A={};T={};V={};C={};
  state.activos.forEach(function(x){A[x.id]=x;});
  state.amenazas.forEach(function(x){T[x.id]=x;});
  state.vulnerabilidades.forEach(function(x){V[x.id]=x;});
  state.controles.forEach(function(x){C[x.id]=x;});
}
function assetValor(a){ return Math.max(a.c,a.i,a.d); }
function tratsDe(r){ return state.tratamientos.filter(function(t){return t.risk_id===r.id;}); }
function inh(r){ return r.probabilidad*r.impacto; }
function eficacia(r){
  var f=1; tratsDe(r).forEach(function(t){
    if(t.estrategia==='Aceptar'||t.estrategia==='Evitar') return;
    if(t.estado!=='Implementado'&&t.estado!=='Verificado') return;
    f*=(1-(t.eficacia||0)/100);
  });
  return Math.min(.9, 1-f);
}
function res(r){
  var ev = tratsDe(r).some(function(t){return t.estrategia==='Evitar'&&(t.estado==='Implementado'||t.estado==='Verificado');});
  if(ev) return 1;
  return Math.max(1, Math.round(inh(r)*(1-eficacia(r))));
}
function reduccion(r){ var i=inh(r); return i? Math.round((i-res(r))/i*100):0; }
function vpr(v){ if(v.cvss_score==null) return null; var x=v.cvss_score+2*(v.epss_score||0); if(v.kev) x=Math.max(x,9); return Math.round(Math.min(10,x)*10)/10; }
function vprNivel(v){ var x=vpr(v); if(x==null)return null; if(x<4)return'Baja'; if(x<7)return'Media'; if(x<9)return'Alta'; return'Crítica'; }
function epssPct(v){ return v.epss_score==null?null:Math.round(v.epss_score*1000)/10; }
function cvssSev(s){ if(s==null)return null; if(s===0)return'Ninguna'; if(s<4)return'Baja'; if(s<7)return'Media'; if(s<9)return'Alta'; return'Crítica'; }
function slaDias(r){ return SLA_DIAS[nivel(inh(r)).n]||90; }
function slaVencido(r){ if(['Controlado','Aceptado','Cerrado'].indexOf(r.estado)>=0) return false; return (r.dias_edad||0)>slaDias(r); }
function slaRestante(r){ return slaDias(r)-(r.dias_edad||0); }
function ces(){
  var num=0,den=0; state.riesgos.forEach(function(r){ var a=A[r.asset_id]; var w=a?assetValor(a):3; num+=res(r)*w; den+=25*w; });
  return den?Math.round(num/den*1000):0;
}
function cesNivel(s){ if(s<200)return{n:'Bajo',c:'bajo'}; if(s<450)return{n:'Medio',c:'medio'}; if(s<700)return{n:'Alto',c:'alto'}; return{n:'Crítico',c:'critico'}; }

// ===================== Motor de valoración y mitigación automática =====================
function ctrlByIso(iso){ return state.controles.filter(function(c){return c.codigo_iso===iso;})[0]; }
function cvssToImpacto(s){ if(s==null)return 0; if(s<2)return 1; if(s<4)return 2; if(s<7)return 3; if(s<9)return 4; return 5; }

// Sugerencia automática de Probabilidad e Impacto a partir del activo (criticidad
// CIA) y de la inteligencia de la vulnerabilidad (CVSS, EPSS, CISA KEV).
function sugerirValoracion(a,t,v){
  var impAsset=a?assetValor(a):3;
  var impCvss=v?cvssToImpacto(v.cvss_score):0;
  var i=Math.max(impAsset,impCvss)||3;
  var p;
  if(v&&v.kev){ p=5; }
  else if(v&&v.epss_score!=null){ var e=v.epss_score; p=e<.05?2:e<.2?3:e<.5?4:5; }
  else { p=3; }
  var motivo=[];
  motivo.push('Impacto '+i+' = máx(valor del activo '+impAsset+(impCvss?', CVSS '+impCvss:'')+')');
  if(v&&v.kev) motivo.push('Probabilidad 5 (explotación activa · CISA KEV)');
  else if(v&&v.epss_score!=null) motivo.push('Probabilidad '+p+' (EPSS '+epssPct(v)+'%)');
  else motivo.push('Probabilidad '+p+' (valor por defecto, sin inteligencia de la vulnerabilidad)');
  return {p:p,i:i,motivo:motivo.join(' · ')};
}

// Reglas de mitigación: vulnerabilidad/categoría/amenaza -> controles ISO 27002
// recomendados con su eficacia estimada.
var MITIG_VULN={
  'Ausencia de MFA':[['8.5',80]],
  'Software sin parches':[['8.8',60],['8.7',40]],
  'Contraseñas débiles':[['8.5',70],['8.3',40]],
  'Falta de cifrado':[['8.24',70],['8.12',40]],
  'Sin respaldos verificados':[['8.13',70]],
  'Personal sin capacitación':[['6.3',55]],
  'Validación de entrada deficiente':[['8.28',75],['8.8',50]],
  'Reglas de firewall permisivas':[['8.20',60]],
  'Privilegios excesivos':[['8.2',60],['8.3',40]],
  'Logs no monitoreados':[['8.16',60],['8.15',40]],
  'Log4Shell (Apache Log4j2 RCE)':[['8.8',60],['8.28',50]],
  'EternalBlue (SMBv1 RCE)':[['8.8',60],['8.20',50]]
};
var MITIG_CAT={ 'Autenticación':[['8.5',70]],'Criptografía':[['8.24',70]],'Red':[['8.20',60]],'Desarrollo':[['8.28',70]],'Gestión de parches':[['8.8',60]],'Continuidad':[['8.13',70]],'Concienciación':[['6.3',55]],'Control de acceso':[['8.2',60]],'Monitoreo':[['8.16',60]] };
var MITIG_THREAT={ 'Ransomware':[['8.13',60]],'Phishing / Ingeniería social':[['6.3',55]],'Denegación de servicio (DDoS)':[['8.20',55]] };

function recomendarControles(r){
  var v=V[r.vuln_id], t=T[r.threat_id];
  var base=(v&&MITIG_VULN[v.nombre]) || (v&&MITIG_CAT[v.categoria]) || [['8.8',50]];
  var extra=(t&&MITIG_THREAT[t.nombre]) || [];
  var seen={}, out=[];
  base.concat(extra).forEach(function(pair){ var iso=pair[0],efi=pair[1],c=ctrlByIso(iso);
    if(!c||seen[iso])return; seen[iso]=1;
    out.push({control_id:c.id,codigo_iso:iso,nombre:c.nombre,eficacia:efi,estrategia:'Mitigar',
      descripcion:'Control recomendado automáticamente'+(v?' para '+v.nombre.toLowerCase():'')+'.'});
  });
  return out;
}
function residualProyectado(r,recs){
  var f=1;
  recs.forEach(function(x){ f*=(1-x.eficacia/100); });
  tratsDe(r).forEach(function(t){ if(t.estrategia==='Aceptar'||t.estrategia==='Evitar')return; if(t.estado!=='Implementado'&&t.estado!=='Verificado')return; f*=(1-(t.eficacia||0)/100); });
  return Math.max(1, Math.round(inh(r)*(1-Math.min(.9,1-f))));
}
window.applyAuto=function(rid){ var r=state.riesgos.filter(function(x){return x.id===rid;})[0]; if(!r)return;
  var recs=recomendarControles(r); if(!recs.length){ toast('No hay controles recomendados para este riesgo.','warn'); return; }
  recs.forEach(function(x){ state.tratamientos.push({risk_id:rid,control_id:x.control_id,estrategia:'Mitigar',descripcion:x.descripcion,responsable:'Asignación automática',eficacia:x.eficacia,estado:'Implementado'}); });
  if(r.estado==='Identificado')r.estado='En Tratamiento';
  saveState(); toast('Mitigación automática aplicada: '+recs.length+' control(es) ISO. Riesgo residual recalculado.','ok'); openRisk(rid);
};
window.applyAutoAll=function(){
  var sin=state.riesgos.filter(function(r){return tratsDe(r).length===0;});
  if(!sin.length){ toast('Todos los riesgos ya tienen tratamiento.','warn'); return; }
  if(!confirm('¿Aplicar mitigación recomendada automáticamente a '+sin.length+' riesgo(s) sin tratar? Se registrarán los controles ISO como implementados.')) return;
  var n=0; sin.forEach(function(r){ recomendarControles(r).forEach(function(x){ state.tratamientos.push({risk_id:r.id,control_id:x.control_id,estrategia:'Mitigar',descripcion:x.descripcion,responsable:'Asignación automática',eficacia:x.eficacia,estado:'Implementado'}); n++; }); if(r.estado==='Identificado')r.estado='En Tratamiento'; });
  saveState(); toast(n+' controles aplicados en '+sin.length+' riesgos. Cálculos actualizados.','ok'); go('panel');
};

// ===================== Helpers de render =====================
function h(s){ return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];}); }
function chip(nv,label){ return '<span class="chip '+nv.c+'">'+h(label!=null?label:nv.n)+'</span>'; }
function el(id){ return document.getElementById(id); }
function toast(msg,kind){ var t=document.createElement('div'); t.className='toast '+(kind||''); t.textContent=msg; el('toasts').appendChild(t); setTimeout(function(){t.style.opacity='0';t.style.transition='opacity .3s';setTimeout(function(){t.remove();},300);},2800); }
var charts=[];
function killCharts(){ charts.forEach(function(c){try{c.destroy();}catch(e){}}); charts=[]; }

// ===================== Navegación =====================
var current='panel';
var NAV=[
  {id:'panel',label:'Panel de monitoreo',ico:'M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z'},
];
function go(view){ current=view;
  document.querySelectorAll('.nav-item').forEach(function(b){ b.classList.toggle('active', b.dataset.view===view); });
  reindex();
  var v = VIEWS[view]||VIEWS.panel;
  killCharts();
  el('content').innerHTML = v();
  if(v.after) v.after();
  el('sidebar').classList.remove('open');
  try{ history.replaceState(null,'','#'+view); }catch(e){}
  window.scrollTo(0,0);
}
window.go=go;

// ===================== Vistas =====================
var VIEWS={};

// ---------- PANEL ----------
VIEWS.panel=function(){
  var rs=state.riesgos, niveles=['Bajo','Medio','Alto','Crítico'];
  var di={Bajo:0,Medio:0,Alto:0,'Crítico':0}, dr={Bajo:0,Medio:0,Alto:0,'Crítico':0};
  var mtx=[[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0]];
  rs.forEach(function(r){ di[nivel(inh(r)).n]++; dr[nivel(res(r)).n]++; mtx[5-r.impacto][r.probabilidad-1]++; });
  var si=rs.reduce(function(a,r){return a+inh(r);},0)||1, sr=rs.reduce(function(a,r){return a+res(r);},0);
  var reduc=Math.round((si-sr)/si*100);
  var cs=ces(), cn=cesNivel(cs);
  var apet=state.meta.apetito, sobre=rs.filter(function(r){return res(r)>apet;}), vencidos=rs.filter(slaVencido);
  var crit=rs.filter(function(r){return res(r)>=10;}).sort(function(a,b){return res(b)-res(a);});
  var trat=state.tratamientos, estC={}; trat.forEach(function(t){estC[t.estado]=(estC[t.estado]||0)+1;});
  var obs=state.observaciones.slice().reverse().slice(0,4);
  var maxCell=Math.max.apply(null,[].concat.apply([],mtx).concat([1]));

  var html='';
  html+=onboarding();
  html+=head('Fase 6 — Monitoreo y supervisión','Panel de riesgo cibernético',
    'Estado consolidado del riesgo organizacional: exposición inherente, eficacia del tratamiento y riesgo residual vigente.',
    '<button class="btn primary" onclick="openNewRisk()">+ Nuevo riesgo</button>');

  html+='<div class="grid g4">'
    +kpi('','Activos valorados',state.activos.length,'Inventario de información')
    +kpi('a','Riesgos identificados',rs.length,crit.length+' requieren atención prioritaria')
    +kpi('','Controles aplicados',trat.length,'Tratamientos ISO/IEC 27002:2022')
    +kpi('g','Reducción de riesgo',reduc+'%','Inherente → residual (global)')
  +'</div>';

  // CES + alertas
  var pct=Math.round(cs/1000*100);
  html+='<div class="grid mt" style="grid-template-columns:1fr 1fr 1fr">'
    +'<div class="card" style="display:flex;align-items:center;gap:18px">'
      +'<div class="ring" style="width:104px;height:104px;background:conic-gradient(var(--'+cn.c+') '+pct+'%,var(--bg-2) 0)"><div style="width:80px;height:80px"><div><div style="font-family:var(--fs-display);font-size:1.5rem;font-weight:800">'+cs+'</div><div class="dim" style="font-size:.6rem">/ 1000</div></div></div></div>'
      +'<div><div class="dim" style="font-size:.72rem;text-transform:uppercase;letter-spacing:.1em">Cyber Exposure Score</div>'
        +'<div style="font-family:var(--fs-display);font-size:1.2rem;font-weight:700;margin:3px 0">Exposición <span style="color:var(--'+cn.c+')">'+cn.n+'</span></div>'
        +'<div class="dim" style="font-size:.76rem;max-width:22ch">Riesgo residual agregado, ponderado por criticidad de activos.</div></div>'
    +'</div>'
    +'<div class="card"'+(sobre.length?' style="border-color:rgba(214,58,58,.4)"':'')+'><div class="k-label">Exceden el apetito de riesgo</div><div class="k-value" style="color:'+(sobre.length?'var(--critico)':'var(--bajo)')+'">'+sobre.length+'</div><div class="k-foot">Residual &gt; '+apet+' (umbral). '+(sobre.length?'Requieren escalamiento.':'Dentro de tolerancia.')+'</div></div>'
    +'<div class="card"'+(vencidos.length?' style="border-color:rgba(232,89,12,.4)"':'')+'><div class="k-label">SLA de remediación vencidos</div><div class="k-value" style="color:'+(vencidos.length?'var(--alto)':'var(--bajo)')+'">'+vencidos.length+'</div><div class="k-foot">Riesgos abiertos fuera de su ventana de tratamiento.</div></div>'
  +'</div>';

  // Automatización: mitigación recomendada para riesgos sin tratar
  var sinTrat=rs.filter(function(r){return tratsDe(r).length===0;});
  if(sinTrat.length){
    html+='<div class="banner mt" style="border-color:rgba(232,89,12,.28);background:linear-gradient(100deg,rgba(232,89,12,.10),rgba(224,168,0,.06))">'
      +'<div class="b-ico" style="background:rgba(232,89,12,.16)"><svg class="ico" viewBox="0 0 24 24" style="color:var(--alto)"><path d="M13 2 3 14h7l-1 8 10-12h-7z"/></svg></div>'
      +'<div style="flex:1"><b>'+sinTrat.length+' riesgo(s) sin tratamiento.</b> <span class="muted">El sistema puede asignar automáticamente los controles ISO/IEC 27002:2022 recomendados y recalcular el riesgo residual.</span></div>'
      +'<button class="btn primary" onclick="applyAutoAll()">⚡ Aplicar mitigación automática</button></div>';
  }

  // Matriz + barras
  html+='<div class="grid g2 mt" style="grid-template-columns:1.05fr .95fr">';
  html+='<div class="card"><div class="card-title">Matriz de riesgo 5×5</div><div class="card-sub">Distribución por Probabilidad × Impacto (riesgo inherente).</div><div class="matrix"><div class="axis">Impacto →</div>';
  for(var f=0;f<5;f++){ for(var c2=0;c2<5;c2++){ var imp=5-f,prob=c2+1,n=mtx[f][c2],col=nivel(imp*prob).col;
    html+='<div class="cell'+(n===0?' empty':'')+'" title="P'+prob+' × I'+imp+' = '+(imp*prob)+'" style="background:'+(n===0?'rgba(255,255,255,.035)':col)+'">'+n+'</div>'; } }
  html+='<div></div>'; for(var p2=1;p2<=5;p2++) html+='<div class="hx">'+p2+'</div>';
  html+='</div><div class="center dim" style="font-size:.72rem;margin-top:2px">Probabilidad →</div>'
    +'<div class="legend"><span><i style="background:var(--bajo)"></i>Bajo (1–4)</span><span><i style="background:var(--medio)"></i>Medio (5–9)</span><span><i style="background:var(--alto)"></i>Alto (10–14)</span><span><i style="background:var(--critico)"></i>Crítico (15–25)</span></div></div>';

  html+='<div class="card"><div class="card-title">Riesgo inherente vs. residual</div><div class="card-sub">Efecto del tratamiento sobre la distribución de niveles.</div>';
  html+='<div class="dim" style="font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:10px">Inherente</div>';
  ['Crítico','Alto','Medio','Bajo'].forEach(function(n){ html+=bar(n,di[n],rs.length,nivel(n==='Crítico'?20:n==='Alto'?12:n==='Medio'?7:2).col); });
  html+='<hr class="divider" style="margin:16px 0"><div class="dim" style="font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:10px">Residual <span class="chip bajo" style="margin-left:6px">−'+reduc+'%</span></div>';
  ['Crítico','Alto','Medio','Bajo'].forEach(function(n){ html+=bar(n,dr[n],rs.length,nivel(n==='Crítico'?20:n==='Alto'?12:n==='Medio'?7:2).col); });
  html+='</div></div>';

  // Charts
  html+='<div class="grid g2 mt" style="grid-template-columns:1.5fr .5fr">'
    +'<div class="card"><div class="card-title">Tendencia de exposición ('+state.snapshots.length+' semanas)</div><div class="card-sub">Evolución del Cyber Exposure Score y de los riesgos críticos.</div><div style="height:240px;position:relative"><canvas id="cTrend"></canvas></div></div>'
    +'<div class="card"><div class="card-title">Riesgo residual</div><div class="card-sub">Por nivel.</div><div style="height:200px;position:relative"><canvas id="cDonut"></canvas></div></div>'
  +'</div>';

  // Prioritarios
  html+='<div class="card mt"><div class="row between"><div><div class="card-title">Riesgos prioritarios (residual ≥ Alto)</div><div class="card-sub">Requieren seguimiento inmediato.</div></div><button class="btn sm" onclick="go(\'riesgos\')">Ver todos</button></div>';
  if(crit.length){ html+='<div class="table-wrap"><table class="data"><thead><tr><th>Código</th><th>Activo</th><th>Amenaza</th><th>Inherente</th><th>Residual</th><th>Estado</th></tr></thead><tbody>';
    crit.slice(0,6).forEach(function(r){ html+='<tr class="clickable" onclick="openRisk('+r.id+')"><td><span class="code">'+h(r.codigo)+'</span></td><td>'+h(A[r.asset_id].nombre)+'</td><td class="muted">'+h(T[r.threat_id].nombre)+'</td><td>'+chip(nivel(inh(r)),inh(r)+' · '+nivel(inh(r)).n)+'</td><td>'+chip(nivel(res(r)),res(r)+' · '+nivel(res(r)).n)+'</td><td><span class="tag">'+h(r.estado)+'</span></td></tr>'; });
    html+='</tbody></table></div>';
  } else html+='<div class="empty"><h3>Sin riesgos prioritarios</h3></div>';
  html+='</div>';

  // Observaciones
  html+='<div class="card mt"><div class="row between"><div><div class="card-title">Comunicación reciente</div><div class="card-sub">Últimas observaciones y recomendaciones (Fase 5).</div></div><button class="btn sm" onclick="go(\'comunicacion\')">Ir a comunicación</button></div><ul style="list-style:none;margin:0;padding:0">';
  if(obs.length) obs.forEach(function(o){ html+='<li class="obs"><div class="obs-meta"><span class="tag'+(o.tipo==='Recomendación'?' brand':'')+'">'+h(o.tipo)+'</span> '+h(o.autor)+'</div><div style="font-size:.88rem">'+h(o.contenido)+'</div></li>'; });
  else html+='<div class="empty" style="padding:24px">Sin observaciones.</div>';
  html+='</ul></div>';

  VIEWS.panel.after=function(){
    var sn=state.snapshots, cMax=Math.max.apply(null,sn.map(function(s){return s.ces;}).concat([1])), krMax=Math.max.apply(null,sn.map(function(s){return s.criticos;}).concat([1]));
    charts.push(new Chart(el('cTrend'),{type:'line',data:{labels:sn.map(function(s){return s.fecha;}),datasets:[
      {label:'Cyber Exposure Score',data:sn.map(function(s){return Math.round(s.ces/cMax*100);}),_r:sn.map(function(s){return s.ces;}),borderColor:'#4c82f7',backgroundColor:'rgba(76,130,247,.12)',borderWidth:2,fill:true,tension:.35,pointRadius:0,pointHoverRadius:5},
      {label:'Riesgos críticos',data:sn.map(function(s){return Math.round(s.criticos/krMax*100);}),_r:sn.map(function(s){return s.criticos;}),borderColor:'#d63a3a',borderWidth:2,borderDash:[5,4],fill:false,tension:.35,pointRadius:0,pointHoverRadius:5}
    ]},options:chartOpts(true)}));
    charts.push(new Chart(el('cDonut'),{type:'doughnut',data:{labels:niveles,datasets:[{data:niveles.map(function(n){return dr[n];}),backgroundColor:['#2e9e5b','#e0a800','#e8590c','#d63a3a'],borderColor:'#182233',borderWidth:2}]},options:{maintainAspectRatio:false,cutout:'62%',plugins:{legend:{position:'bottom'}}}}));
  };
  return html;
};

// ---------- ACTIVOS ----------
VIEWS.activos=function(){
  var html=head('Fase 1 — Valoración de activos','Inventario de activos de información',
    'Registro y clasificación de activos con valoración CIA (Confidencialidad, Integridad, Disponibilidad) en escala 1–5. El valor del activo es la dimensión más crítica.',
    '<button class="btn" onclick="go(\'importar\')">Importar Excel/CSV</button><button class="btn primary" onclick="openNewAsset()">+ Nuevo activo</button>');
  if(!state.activos.length){ return html+'<div class="card"><div class="empty"><h3>No hay activos</h3><p>Registre activos manualmente o impórtelos desde Excel.</p><div class="row" style="justify-content:center;margin-top:14px"><button class="btn" onclick="go(\'importar\')">Importar Excel</button><button class="btn primary" onclick="openNewAsset()">Nuevo activo</button></div></div></div>'; }
  html+='<div class="table-wrap"><table class="data"><thead><tr><th>Código</th><th>Activo</th><th>Tipo</th><th>Propietario</th><th class="center">C</th><th class="center">I</th><th class="center">D</th><th>Valor</th><th>Riesgos</th></tr></thead><tbody>';
  state.activos.forEach(function(a){ var nr=state.riesgos.filter(function(r){return r.asset_id===a.id;}).length; var nv=nivel(assetValor(a)*5);
    html+='<tr><td><span class="code">'+h(a.codigo)+'</span></td><td><div class="stack" style="gap:2px"><b>'+h(a.nombre)+'</b><span class="dim" style="font-size:.78rem">'+h((a.descripcion||'').slice(0,64))+'</span></div></td><td><span class="tag">'+h(a.tipo)+'</span></td><td class="muted">'+h(a.propietario||'—')+'</td><td class="center mono">'+a.c+'</td><td class="center mono">'+a.i+'</td><td class="center mono">'+a.d+'</td><td>'+chip(nv,assetValor(a)+' · '+ESCALA[assetValor(a)])+'</td><td class="center mono">'+nr+'</td></tr>'; });
  html+='</tbody></table></div>';
  return html;
};

// ---------- RIESGOS ----------
VIEWS.riesgos=function(){
  var rs=state.riesgos.slice().sort(function(a,b){return res(b)-res(a);});
  var html=head('Fase 2 — Identificación y análisis de riesgos','Registro de riesgos',
    'Cada riesgo combina un activo, una amenaza y una vulnerabilidad, valorado por Probabilidad × Impacto. Ordenado por riesgo residual.',
    '<button class="btn" onclick="go(\'importar\')">Importar Excel/CSV</button><button class="btn primary" onclick="openNewRisk()">+ Nuevo riesgo</button>');
  if(!rs.length){ return html+'<div class="card"><div class="empty"><h3>No hay riesgos</h3><p>Registre riesgos o impórtelos desde Excel.</p></div></div>'; }
  html+='<div class="card" style="padding:14px 16px;margin-bottom:14px"><div class="row"><input class="control" id="fq" style="max-width:340px" placeholder="Buscar por código, activo, amenaza..." oninput="filterRisks()"><select class="control" id="fn" style="max-width:200px" onchange="filterRisks()"><option value="">Todos los niveles (residual)</option><option value="critico">Crítico</option><option value="alto">Alto</option><option value="medio">Medio</option><option value="bajo">Bajo</option></select><span class="dim" id="fc" style="font-size:.82rem;margin-left:auto">'+rs.length+' riesgos</span></div></div>';
  html+='<div class="table-wrap"><table class="data" id="rtab"><thead><tr><th>Código</th><th>Activo</th><th>Amenaza / Vulnerabilidad</th><th>P×I</th><th>Inherente</th><th>Residual</th><th>Estado</th></tr></thead><tbody>';
  rs.forEach(function(r){ var busca=(r.codigo+' '+A[r.asset_id].nombre+' '+T[r.threat_id].nombre+' '+V[r.vuln_id].nombre).toLowerCase();
    html+='<tr class="clickable" data-b="'+h(busca)+'" data-n="'+nivel(res(r)).c+'" onclick="openRisk('+r.id+')"><td><span class="code">'+h(r.codigo)+'</span></td><td>'+h(A[r.asset_id].nombre)+'</td><td class="stack" style="gap:2px"><span>'+h(T[r.threat_id].nombre)+'</span><span class="dim" style="font-size:.78rem">'+h(V[r.vuln_id].nombre)+'</span></td><td class="mono muted">'+r.probabilidad+'×'+r.impacto+'</td><td>'+chip(nivel(inh(r)),inh(r)+' · '+nivel(inh(r)).n)+'</td><td>'+chip(nivel(res(r)),res(r)+' · '+nivel(res(r)).n)+(reduccion(r)>0?' <span class="dim" style="font-size:.74rem">−'+reduccion(r)+'%</span>':'')+'</td><td><span class="tag">'+h(r.estado)+'</span></td></tr>'; });
  html+='</tbody></table></div>';
  return html;
};

// ---------- INTELIGENCIA ----------
VIEWS.inteligencia=function(){
  var vs=state.vulnerabilidades.slice().sort(function(a,b){var x=vpr(a),y=vpr(b);return (y==null?-1:y)-(x==null?-1:x);});
  var enr=vs.filter(function(v){return v.cvss_score!=null;});
  var html=head('Cyber Threat Intelligence · ISO/IEC 27002:2022 — 5.7','Inteligencia de amenazas',
    'Enriquecimiento de vulnerabilidades con CVSS 3.1, EPSS (probabilidad de explotación) y CISA KEV (explotación activa). El VPR prioriza combinando severidad técnica y amenaza real.');
  html+='<div class="grid g4">'
    +kpi('','Vulnerabilidades enriquecidas',enr.length,'de '+vs.length+' en catálogo')
    +kpi('r','En CISA KEV',vs.filter(function(v){return v.kev;}).length,'Explotadas activamente')
    +kpi('a','VPR crítico (≥ 9)',enr.filter(function(v){return vpr(v)>=9;}).length,'Prioridad máxima de remediación')
    +kpi('','EPSS alto (≥ 50%)',enr.filter(function(v){return (v.epss_score||0)>=.5;}).length,'Alta probabilidad de explotación')
  +'</div>';
  html+='<div class="card mt" style="background:var(--bg-2);padding:14px 18px"><div class="dim" style="font-size:.8rem"><b>VPR (Vulnerability Priority Rating):</b> prioridad 0–10 = CVSS + hasta +2 por EPSS; si la vulnerabilidad está en CISA KEV se eleva a un piso de 9.0. Enfoque transparente inspirado en Tenable VPR.</div></div>';
  html+='<div class="card mt"><div class="card-title">Vulnerabilidades priorizadas por VPR</div><div class="card-sub">Escriba un CVE y pulse ↻ para enriquecer (catálogo de demostración local).</div><div class="table-wrap"><table class="data"><thead><tr><th>Vulnerabilidad</th><th>CVE</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>VPR</th><th>Enriquecer</th></tr></thead><tbody>';
  vs.forEach(function(v){ var vn=vprNivel(v), vc=vn==='Crítica'?'critico':vn==='Alta'?'alto':vn==='Media'?'medio':'bajo';
    var cc=v.cvss_score==null?'':(v.cvss_score>=9?'critico':v.cvss_score>=7?'alto':v.cvss_score>=4?'medio':'bajo');
    html+='<tr><td class="stack" style="gap:2px"><b>'+h(v.nombre)+'</b><span class="dim" style="font-size:.76rem">'+h(v.categoria||'')+'</span></td>'
      +'<td>'+(v.cve_id?'<span class="code">'+h(v.cve_id)+'</span>':'<span class="dim">—</span>')+'</td>'
      +'<td>'+(v.cvss_score!=null?'<span class="chip '+cc+'">'+v.cvss_score+'</span>':'<span class="dim">—</span>')+'</td>'
      +'<td>'+(epssPct(v)!=null?'<span class="mono">'+epssPct(v)+'%</span>':'<span class="dim">—</span>')+'</td>'
      +'<td>'+(v.kev?'<span class="chip critico">KEV</span>':'<span class="dim">no</span>')+'</td>'
      +'<td>'+(vpr(v)!=null?'<span class="chip '+vc+'">'+vpr(v)+' · '+vn+'</span>':'<span class="dim">—</span>')+'</td>'
      +'<td><div class="row" style="gap:6px;flex-wrap:nowrap"><input class="control mono" id="cve'+v.id+'" style="padding:6px 9px;font-size:.78rem;width:150px" value="'+h(v.cve_id||'')+'" placeholder="CVE-AAAA-NNNN"><button class="btn sm primary" onclick="enrich('+v.id+')">↻</button></div></td></tr>'; });
  html+='</tbody></table></div><div class="dim mt" style="font-size:.78rem">Pruebe <span class="code">CVE-2021-44228</span>, <span class="code">CVE-2019-0708</span> o <span class="code">CVE-2020-1472</span>. La versión completa consulta NVD, EPSS y CISA KEV en vivo.</div></div>';
  return html;
};

// ---------- CUMPLIMIENTO ----------
VIEWS.cumplimiento=function(){
  var total=state.controles.length;
  var aplicados={}; state.tratamientos.forEach(function(t){ if(t.control_id) aplicados[t.control_id]=1; });
  var nAp=Object.keys(aplicados).length, cob=total?Math.round(nAp/total*100):0;
  var temas={}; state.controles.forEach(function(c){ var x=temas[c.tema]=temas[c.tema]||{t:0,a:0}; x.t++; if(aplicados[c.id])x.a++; });
  var funcs=[['Govern','Gobernar','Estrategia, políticas y supervisión del riesgo.','#8b5cf6'],['Identify','Identificar','Conocer activos, riesgos y contexto.','#4c82f7'],['Protect','Proteger','Salvaguardas para limitar el impacto.','#34d3c0'],['Detect','Detectar','Identificar eventos y anomalías.','#e0a800'],['Respond','Responder','Acciones ante un incidente detectado.','#e8590c'],['Recover','Recuperar','Restaurar capacidades tras un incidente.','#2e9e5b']];
  var tc={Organizacional:'var(--brand)',Personas:'var(--brand-2)','Físico':'var(--medio)','Tecnológico':'var(--alto)'};
  var html=head('Marcos internacionales','Cobertura de cumplimiento',
    'Alineación del programa de seguridad con ISO/IEC 27001 Anexo A / 27002:2022 y NIST Cybersecurity Framework 2.0, según los controles efectivamente aplicados.');
  html+='<div class="grid g2" style="grid-template-columns:.8fr 1.2fr">';
  html+='<div class="card" style="display:flex;align-items:center;gap:20px"><div class="ring" style="width:120px;height:120px;background:conic-gradient(var(--brand) '+cob+'%,var(--bg-2) 0)"><div style="width:92px;height:92px"><div style="font-family:var(--fs-display);font-size:1.9rem;font-weight:800">'+cob+'%</div></div></div><div><div class="dim" style="font-size:.72rem;text-transform:uppercase;letter-spacing:.1em">ISO/IEC 27002:2022</div><div style="font-family:var(--fs-display);font-size:1.15rem;font-weight:700;margin:4px 0">'+nAp+' de '+total+' controles aplicados</div><div class="dim" style="font-size:.8rem;max-width:30ch">Controles del catálogo con al menos un tratamiento asociado a un riesgo.</div></div></div>';
  html+='<div class="card"><div class="card-title">Cobertura por tema ISO 27002:2022</div><div class="card-sub">Los 4 temas de la norma (93 controles totales).</div>';
  Object.keys(temas).forEach(function(k){ var x=temas[k]; html+=bar(k,x.a,x.t,tc[k]||'var(--brand)',x.a+'/'+x.t); });
  html+='</div></div>';
  html+='<div class="card mt"><div class="card-title">NIST Cybersecurity Framework 2.0 — cobertura por función</div><div class="card-sub">Distribución de los controles aplicados en las seis funciones del marco.</div><div class="grid" style="grid-template-columns:repeat(6,1fr);gap:14px;margin-top:14px">';
  funcs.forEach(function(f){ var cat=state.controles.filter(function(c){return c.nist_csf===f[0];}), ap=cat.filter(function(c){return aplicados[c.id];}), pc=cat.length?Math.round(ap.length/cat.length*100):0;
    html+='<div class="card" style="padding:16px;text-align:center;background:var(--bg-2)"><div class="ring" style="width:44px;height:44px;margin:0 auto 10px;background:conic-gradient('+f[3]+' '+pc+'%,var(--surface-2) 0)"><div style="width:32px;height:32px;font-family:var(--fs-mono);font-size:.68rem;font-weight:600">'+pc+'%</div></div><div style="font-family:var(--fs-display);font-weight:700;font-size:.92rem">'+f[1]+'</div><div class="dim" style="font-size:.68rem;margin:4px 0">'+ap.length+'/'+cat.length+' controles</div><div class="dim" style="font-size:.68rem;line-height:1.3">'+f[2]+'</div></div>'; });
  html+='</div></div>';
  html+='<div class="card mt" style="background:var(--bg-2);padding:14px 18px"><div class="dim" style="font-size:.8rem"><b>Interpretación:</b> una cobertura baja en Detectar, Responder o Recuperar indica que la organización invierte en prevención pero está menos preparada para gestionar incidentes ya materializados.</div></div>';
  return html;
};

// ---------- TRATAMIENTO (Fase 3) ----------
VIEWS.tratamiento=function(){
  var rs=state.riesgos;
  var sinTrat=rs.filter(function(r){return tratsDe(r).length===0;});
  var estr={Mitigar:0,Transferir:0,Aceptar:0,Evitar:0}, implementados=0;
  state.tratamientos.forEach(function(t){ if(estr[t.estrategia]!=null)estr[t.estrategia]++; if(t.estado==='Implementado'||t.estado==='Verificado')implementados++; });
  var dominante='Mitigar',mx=-1; Object.keys(estr).forEach(function(k){ if(estr[k]>mx){mx=estr[k];dominante=k;} });
  var html=head('Fase 3 — Tratamiento del riesgo','Plan de tratamiento del riesgo',
    'Definición de la estrategia (Mitigar / Transferir / Aceptar / Evitar) y de los controles ISO/IEC 27002:2022 aplicados a cada riesgo, con responsable y estado de implementación.',
    (sinTrat.length?'<button class="btn primary" onclick="applyAutoAll()">⚡ Mitigación automática ('+sinTrat.length+')</button>':''));
  html+='<div class="grid g4">'
    +kpi('','Tratamientos definidos',state.tratamientos.length,'Controles ISO asociados a riesgos')
    +kpi('g','Controles efectivos',implementados,'Implementados o verificados')
    +kpi(sinTrat.length?'a':'','Riesgos sin tratar',sinTrat.length,sinTrat.length?'Requieren un plan de tratamiento':'Todos los riesgos tienen plan')
    +kpi('','Estrategia dominante',dominante,'Opción de tratamiento más usada')
  +'</div>';
  html+='<div class="card mt"><div class="card-title">Distribución por estrategia de tratamiento</div><div class="card-sub">Opciones de tratamiento del riesgo (ISO/IEC 27005).</div>';
  var stratCol={Mitigar:'#4c82f7',Transferir:'#8b5cf6',Aceptar:'#e0a800',Evitar:'#2e9e5b'}, totT=state.tratamientos.length||1;
  ['Mitigar','Transferir','Aceptar','Evitar'].forEach(function(k){ html+=bar(k,estr[k],totT,stratCol[k],estr[k]); });
  html+='</div>';
  if(sinTrat.length){
    html+='<div class="card mt"><div class="card-title">Riesgos sin tratamiento <span class="chip alto" style="margin-left:6px">'+sinTrat.length+'</span></div><div class="card-sub">El sistema recomienda controles ISO/IEC 27002:2022 y calcula el residual proyectado. Aplique la mitigación con un clic.</div><div class="table-wrap" style="margin-top:10px"><table class="data"><thead><tr><th>Código</th><th>Activo</th><th>Amenaza</th><th>Inherente</th><th>Residual proyectado</th><th></th></tr></thead><tbody>';
    sinTrat.forEach(function(r){ var recs=recomendarControles(r), proj=residualProyectado(r,recs), redp=Math.round((inh(r)-proj)/inh(r)*100);
      html+='<tr><td><span class="code">'+h(r.codigo)+'</span></td><td>'+h(A[r.asset_id].nombre)+'</td><td class="muted">'+h(T[r.threat_id].nombre)+'</td><td>'+chip(nivel(inh(r)),inh(r)+' · '+nivel(inh(r)).n)+'</td><td>'+chip(nivel(proj),proj+' · '+nivel(proj).n)+' <span class="dim" style="font-size:.74rem">−'+redp+'%</span></td><td><div class="row" style="gap:6px;flex-wrap:nowrap;justify-content:flex-end"><button class="btn sm primary" onclick="applyAuto('+r.id+')">⚡ Aplicar</button><button class="btn sm" onclick="openTreatment('+r.id+')">+ Manual</button></div></td></tr>'; });
    html+='</tbody></table></div></div>';
  }
  html+='<div class="card mt"><div class="card-title">Tratamientos registrados</div><div class="card-sub">Todos los controles definidos, agrupados por riesgo. Clic para ver el detalle.</div>';
  if(state.tratamientos.length){
    html+='<div class="table-wrap" style="margin-top:10px"><table class="data"><thead><tr><th>Riesgo</th><th>Estrategia</th><th>Control ISO 27002:2022</th><th>Responsable</th><th>Eficacia</th><th>Estado</th></tr></thead><tbody>';
    rs.forEach(function(r){ tratsDe(r).forEach(function(t2){ var ct=t2.control_id?C[t2.control_id]:null;
      html+='<tr class="clickable" onclick="openRisk('+r.id+')"><td><span class="code">'+h(r.codigo)+'</span></td><td><span class="tag'+(['Mitigar','Evitar'].indexOf(t2.estrategia)>=0?' brand':'')+'">'+h(t2.estrategia)+'</span></td><td>'+(ct?'<span class="code">'+h(ct.codigo_iso)+'</span> <span class="dim" style="font-size:.8rem">'+h(ct.nombre)+'</span>':'<span class="dim">—</span>')+'</td><td class="muted">'+h(t2.responsable||'—')+'</td><td class="mono">'+(t2.eficacia||0)+'%</td><td><span class="tag">'+h(t2.estado)+'</span></td></tr>'; }); });
    html+='</tbody></table></div>';
  } else html+='<div class="empty" style="padding:24px">Sin tratamientos registrados aún. Use la mitigación automática o añada uno desde el detalle de un riesgo.</div>';
  html+='</div>';
  return html;
};

// ---------- RIESGO RESIDUAL (Fase 4) ----------
VIEWS.residual=function(){
  var rs=state.riesgos.slice().sort(function(a,b){return res(b)-res(a);});
  var si=rs.reduce(function(a,r){return a+inh(r);},0)||1, sr=rs.reduce(function(a,r){return a+res(r);},0);
  var reduc=Math.round((si-sr)/si*100);
  var apet=state.meta.apetito, sobre=rs.filter(function(r){return res(r)>apet;});
  var di={Bajo:0,Medio:0,Alto:0,'Crítico':0}, dr={Bajo:0,Medio:0,Alto:0,'Crítico':0};
  rs.forEach(function(r){ di[nivel(inh(r)).n]++; dr[nivel(res(r)).n]++; });
  var html=head('Fase 4 — Cálculo de riesgo residual','Riesgo residual',
    'Riesgo remanente tras aplicar los controles. Se recalcula automáticamente: Residual = Inherente × (1 − eficacia combinada). Solo los controles Implementados o Verificados reducen el riesgo; la reducción máxima es del 90 %.');
  html+='<div class="grid g4">'
    +kpi('a','Exposición inherente',si,'Suma de P×I sin controles')
    +kpi('g','Exposición residual',sr,'Tras los controles aplicados')
    +kpi('g','Reducción global',reduc+'%','Efecto agregado del tratamiento')
    +kpi(sobre.length?'r':'','Exceden el apetito',sobre.length,'Residual > '+apet+' (umbral ISO 31000)')
  +'</div>';
  html+='<div class="card mt" style="background:var(--bg-2);padding:14px 18px"><div class="dim" style="font-size:.82rem"><b>Metodología:</b> la eficacia combinada de n controles = 1 − Π(1 − eficaciaᵢ). La estrategia <b>Evitar</b> elimina el riesgo (residual mínimo); <b>Aceptar</b> no reduce el valor. El residual nunca baja de 1.</div></div>';
  html+='<div class="card mt"><div class="card-title">Inherente vs. residual por nivel</div><div class="card-sub">Migración de riesgos entre niveles gracias al tratamiento.</div>';
  html+='<div class="dim" style="font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;margin:8px 0 10px">Inherente</div>';
  ['Crítico','Alto','Medio','Bajo'].forEach(function(n){ html+=bar(n,di[n],rs.length,nivel(n==='Crítico'?20:n==='Alto'?12:n==='Medio'?7:2).col); });
  html+='<hr class="divider" style="margin:16px 0"><div class="dim" style="font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:10px">Residual <span class="chip bajo" style="margin-left:6px">−'+reduc+'%</span></div>';
  ['Crítico','Alto','Medio','Bajo'].forEach(function(n){ html+=bar(n,dr[n],rs.length,nivel(n==='Crítico'?20:n==='Alto'?12:n==='Medio'?7:2).col); });
  html+='</div>';
  html+='<div class="card mt"><div class="card-title">Cálculo por riesgo</div><div class="card-sub">Ordenado por riesgo residual. Clic para ver el detalle y su plan de tratamiento.</div><div class="table-wrap" style="margin-top:10px"><table class="data"><thead><tr><th>Código</th><th>Activo</th><th>Inherente</th><th>Eficacia controles</th><th>Residual</th><th>Reducción</th><th>vs. apetito</th></tr></thead><tbody>';
  rs.forEach(function(r){ var ef=Math.round(eficacia(r)*100), over=res(r)>apet;
    html+='<tr class="clickable" onclick="openRisk('+r.id+')"><td><span class="code">'+h(r.codigo)+'</span></td><td>'+h(A[r.asset_id].nombre)+'</td><td>'+chip(nivel(inh(r)),inh(r)+' ('+r.probabilidad+'×'+r.impacto+')')+'</td><td class="mono">'+ef+'%</td><td>'+chip(nivel(res(r)),res(r)+' · '+nivel(res(r)).n)+'</td><td class="mono'+(reduccion(r)>0?'':' dim')+'">'+(reduccion(r)>0?'−'+reduccion(r)+'%':'—')+'</td><td>'+(over?'<span class="chip critico">Excede</span>':'<span class="chip bajo">Dentro</span>')+'</td></tr>'; });
  html+='</tbody></table></div></div>';
  return html;
};

// ---------- COMUNICACIÓN (Fase 5) ----------
VIEWS.comunicacion=function(){
  var obs=state.observaciones.slice().reverse();
  var html=head('Fase 5 — Comunicación y consulta','Comunicación y generación de informes',
    'Registro de observaciones, hallazgos y recomendaciones de las partes interesadas, y generación del informe ejecutivo de riesgos para la dirección.',
    '<button class="btn primary" onclick="generarInforme()">📄 Generar informe ejecutivo</button>');
  html+='<div class="grid g2" style="grid-template-columns:.9fr 1.1fr">';
  html+='<div class="card"><div class="card-title">Registrar observación</div><div class="card-sub">Comunique un hallazgo o una recomendación al equipo de gestión de riesgos.</div>'
    +'<form onsubmit="return addObs(this)" style="margin-top:12px"><div class="form-grid" style="grid-template-columns:1fr 1fr">'
    +field('Tipo','<select class="control" name="tipo">'+['Observación','Recomendación','Hallazgo'].map(function(x){return '<option>'+x+'</option>';}).join('')+'</select>')
    +field('Autor','<input class="control" name="autor" placeholder="Su nombre / rol">')
    +'<div class="full">'+field('Riesgo relacionado (opcional)','<select class="control" name="risk_id"><option value="">— General —</option>'+selOptions(state.riesgos,'id',function(r){return r.codigo+' · '+T[r.threat_id].nombre;})+'</select>')+'</div>'
    +'<div class="full">'+field('Contenido *','<textarea class="control" name="contenido" placeholder="Describa la observación o recomendación..." required></textarea>')+'</div>'
    +'</div><div class="row" style="margin-top:14px"><button class="btn primary" type="submit">Registrar</button></div></form></div>';
  html+='<div class="card"><div class="card-title">Bitácora de comunicación</div><div class="card-sub">'+obs.length+' registro(s), del más reciente al más antiguo.</div><ul style="list-style:none;margin:12px 0 0;padding:0">';
  if(obs.length) obs.forEach(function(o){ var r=o.risk_id?state.riesgos.filter(function(x){return x.id===o.risk_id;})[0]:null;
    html+='<li class="obs"><div class="obs-meta"><span class="tag'+(o.tipo==='Recomendación'?' brand':'')+'">'+h(o.tipo)+'</span> '+h(o.autor||'Anónimo')+(o.fecha?' · <span class="dim">'+h(o.fecha)+'</span>':'')+(r?' · <span class="code">'+h(r.codigo)+'</span>':'')+'</div><div style="font-size:.9rem">'+h(o.contenido)+'</div></li>'; });
  else html+='<div class="empty" style="padding:24px">Sin observaciones. Registre la primera con el formulario.</div>';
  html+='</ul></div></div>';
  return html;
};
window.addObs=function(form){ var d=formData(form); if(!d.contenido||d.contenido.length<5){ toast('Escriba el contenido de la observación (mín. 5 caracteres).','err'); return false; }
  state.observaciones.push({tipo:d.tipo||'Observación',autor:d.autor||'Anónimo',contenido:d.contenido,risk_id:d.risk_id?+d.risk_id:null,fecha:new Date().toISOString().slice(0,10)});
  saveState(); toast('Observación registrada.','ok'); go('comunicacion'); return false;
};
window.generarInforme=function(){
  reindex();
  var rs=state.riesgos, cs=ces(), cn=cesNivel(cs);
  var si=rs.reduce(function(a,r){return a+inh(r);},0)||1, sr=rs.reduce(function(a,r){return a+res(r);},0);
  var reduc=Math.round((si-sr)/si*100), apet=state.meta.apetito;
  var sobre=rs.filter(function(r){return res(r)>apet;});
  var top=rs.slice().sort(function(a,b){return res(b)-res(a);}).slice(0,8);
  var recs=state.observaciones.filter(function(o){return o.tipo==='Recomendación';});
  var dr={Bajo:0,Medio:0,Alto:0,'Crítico':0}; rs.forEach(function(r){ dr[nivel(res(r)).n]++; });
  var fecha=new Date().toLocaleDateString('es-EC',{year:'numeric',month:'long',day:'numeric'});
  var org=h(state.meta.organizacion);
  var css='body{font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1a2230;margin:0;padding:40px;max-width:900px;margin:0 auto;line-height:1.5}'
    +'h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.05rem;margin:26px 0 10px;border-bottom:2px solid #4c82f7;padding-bottom:5px;color:#123}'
    +'.sub{color:#667;font-size:.9rem}.kpis{display:flex;gap:14px;flex-wrap:wrap;margin:16px 0}'
    +'.k{flex:1;min-width:150px;border:1px solid #dde3ec;border-radius:10px;padding:14px 16px;background:#f7f9fc}'
    +'.k b{display:block;font-size:1.7rem;color:#123}.k span{font-size:.78rem;color:#667;text-transform:uppercase;letter-spacing:.05em}'
    +'table{width:100%;border-collapse:collapse;font-size:.86rem;margin-top:6px}th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #e6ebf2}th{background:#f0f4fa;font-size:.76rem;text-transform:uppercase;letter-spacing:.04em;color:#556}'
    +'.tag{display:inline-block;padding:2px 8px;border-radius:20px;font-size:.75rem;font-weight:600;color:#fff}'
    +'.bajo{background:#2e9e5b}.medio{background:#e0a800}.alto{background:#e8590c}.critico{background:#d63a3a}'
    +'.foot{margin-top:34px;padding-top:12px;border-top:1px solid #e6ebf2;color:#889;font-size:.78rem}'
    +'ul{margin:6px 0;padding-left:20px}li{margin:5px 0}'
    +'@media print{body{padding:0}button{display:none}}';
  function tg(n){var c=nivel(n==='Crítico'?20:n==='Alto'?12:n==='Medio'?7:2).c;return '<span class="tag '+c+'">'+n+'</span>';}
  var body='<h1>Informe ejecutivo de riesgos cibernéticos</h1>'
    +'<div class="sub">'+org+' · Metodología GRC-360 · '+fecha+'</div>'
    +'<h2>1. Resumen ejecutivo</h2>'
    +'<div class="kpis"><div class="k"><b>'+cs+'</b><span>Cyber Exposure Score / 1000 · '+cn.n+'</span></div>'
      +'<div class="k"><b>'+rs.length+'</b><span>Riesgos gestionados</span></div>'
      +'<div class="k"><b>'+reduc+'%</b><span>Reducción de exposición</span></div>'
      +'<div class="k"><b>'+sobre.length+'</b><span>Exceden el apetito ('+apet+')</span></div></div>'
    +'<p>Tras la valoración de <b>'+state.activos.length+' activos</b> y el análisis de <b>'+rs.length+' riesgos</b>, la organización presenta una exposición cibernética <b>'+cn.n.toLowerCase()+'</b>. La aplicación de '+state.tratamientos.length+' controles ISO/IEC 27002:2022 ha reducido la exposición agregada en un <b>'+reduc+'%</b> (de '+si+' a '+sr+' puntos de riesgo). '+(sobre.length?'<b>'+sobre.length+'</b> riesgo(s) permanecen por encima del apetito de riesgo definido ('+apet+') y requieren escalamiento a la dirección.':'Ningún riesgo supera el apetito de riesgo definido.')+'</p>'
    +'<h2>2. Distribución del riesgo residual</h2>'
    +'<p>'+tg('Crítico')+' '+dr['Crítico']+' &nbsp; '+tg('Alto')+' '+dr.Alto+' &nbsp; '+tg('Medio')+' '+dr.Medio+' &nbsp; '+tg('Bajo')+' '+dr.Bajo+'</p>'
    +'<h2>3. Riesgos prioritarios</h2>'
    +'<table><thead><tr><th>Código</th><th>Activo</th><th>Amenaza</th><th>Inherente</th><th>Residual</th><th>Estado</th></tr></thead><tbody>'
    +top.map(function(r){return '<tr><td>'+h(r.codigo)+'</td><td>'+h(A[r.asset_id].nombre)+'</td><td>'+h(T[r.threat_id].nombre)+'</td><td>'+tg(nivel(inh(r)).n)+' '+inh(r)+'</td><td>'+tg(nivel(res(r)).n)+' '+res(r)+'</td><td>'+h(r.estado)+'</td></tr>';}).join('')
    +'</tbody></table>'
    +'<h2>4. Recomendaciones</h2>'
    +(recs.length?'<ul>'+recs.map(function(o){return '<li>'+h(o.contenido)+' <i style="color:#889">— '+h(o.autor||'')+'</i></li>';}).join('')+'</ul>':'<p>Se recomienda mantener el monitoreo continuo, priorizar los riesgos que exceden el apetito y verificar la eficacia de los controles implementados.</p>')
    +'<div class="foot">Documento generado automáticamente por CyberRisk 360 — Sistema de gestión de riesgos cibernéticos (metodología GRC-360). Alineado con ISO/IEC 27001, 27002:2022, 27005 e ISO 31000.</div>'
    +'<button onclick="window.print()" style="margin-top:20px;padding:10px 18px;border:0;border-radius:8px;background:#4c82f7;color:#fff;font-weight:600;cursor:pointer">Imprimir / Guardar como PDF</button>';
  var full='<!doctype html><html lang="es"><head><meta charset="utf-8"><title>Informe ejecutivo · '+org+'</title><style>'+css+'</style></head><body>'+body+'</body></html>';
  var w=window.open('','_blank');
  if(!w){ var b=new Blob([full],{type:'text/html'}); var a=document.createElement('a'); a.href=URL.createObjectURL(b); a.download='informe-ejecutivo-riesgos.html'; a.click(); toast('Informe descargado (permita ventanas emergentes para verlo en pantalla).','ok'); return; }
  w.document.write(full); w.document.close(); toast('Informe ejecutivo generado.','ok');
};

// ---------- IMPORTAR ----------
VIEWS.importar=function(){
  var html=head('Carga de datos','Importar desde Excel o CSV',
    'Cargue activos o riesgos de forma masiva desde un archivo .xlsx, .xls o .csv. Descargue la plantilla, complétela y súbala.');
  html+='<div class="grid g2">';
  // Activos
  html+='<div class="card"><div class="card-title">Importar activos</div><div class="card-sub">Columnas: codigo, nombre, tipo, propietario, confidencialidad, integridad, disponibilidad, descripcion.</div>'
    +'<div class="steps"><span class="step"><b>1</b>Descargue la plantilla</span><span class="step"><b>2</b>Complete sus datos</span><span class="step"><b>3</b>Suba el archivo</span></div>'
    +'<div class="row" style="margin:10px 0 14px"><button class="btn sm" onclick="tpl(\'activos\')">Descargar plantilla (.xlsx)</button><button class="btn sm ghost" onclick="tplCsv(\'activos\')">.csv</button></div>'
    +dropzone('activos')
  +'</div>';
  // Riesgos
  html+='<div class="card"><div class="card-title">Importar riesgos</div><div class="card-sub">Columnas: codigo, activo_codigo, amenaza, vulnerabilidad, probabilidad, impacto, estado, descripcion.</div>'
    +'<div class="steps"><span class="step"><b>1</b>Descargue la plantilla</span><span class="step"><b>2</b>Complete sus datos</span><span class="step"><b>3</b>Suba el archivo</span></div>'
    +'<div class="row" style="margin:10px 0 14px"><button class="btn sm" onclick="tpl(\'riesgos\')">Descargar plantilla (.xlsx)</button><button class="btn sm ghost" onclick="tplCsv(\'riesgos\')">.csv</button></div>'
    +dropzone('riesgos')
  +'</div>';
  html+='</div>';
  html+='<div class="card mt" style="background:var(--bg-2);padding:14px 18px"><div class="dim" style="font-size:.8rem"><b>Sugerencia:</b> los códigos deben ser únicos. Para riesgos, <b>activo_codigo</b> debe coincidir con un activo existente; las amenazas y vulnerabilidades nuevas se agregan automáticamente al catálogo. Probabilidad e impacto van de 1 a 5.</div></div>';
  html+='<div id="preview"></div>';
  VIEWS.importar.after=function(){ ['activos','riesgos'].forEach(bindDrop); };
  return html;
};

// ===================== Componentes de render =====================
function onboarding(){
  if(localStorage.getItem('crk.seen')) return '';
  return '<div class="banner"><div class="b-ico"><svg class="ico" viewBox="0 0 24 24" style="color:var(--brand)"><path d="M12 2 4 6v6c0 4 3 7 8 9 5-2 8-5 8-9V6z"/><path d="M9 12l2 2 4-4"/></svg></div>'
    +'<div style="flex:1"><b>Bienvenido a CyberRisk 360.</b> <span class="muted">Está viendo un caso de ejemplo (FinTech Andina S.A.) con 6 activos y 12 riesgos ya cargados. Explore los módulos en el menú, o cargue sus propios datos desde Excel.</span></div>'
    +'<button class="btn sm" onclick="go(\'importar\')">Importar mis datos</button><button class="btn sm ghost" onclick="dismiss()">Entendido</button></div>';
}
window.dismiss=function(){ localStorage.setItem('crk.seen','1'); go(current); };

function head(eye,title,desc,actions){ return '<div class="page-head"><div><div class="eyebrow">'+h(eye)+'</div><h1>'+h(title)+'</h1><p>'+h(desc)+'</p></div>'+(actions?'<div class="row">'+actions+'</div>':'')+'</div>'; }
function kpi(cls,label,val,foot){ return '<div class="kpi '+cls+'"><div class="k-label">'+h(label)+'</div><div class="k-value">'+val+'</div><div class="k-foot">'+h(foot)+'</div></div>'; }
function bar(label,val,total,col,valTxt){ var w=total?Math.round(val/total*100):0; return '<div class="bar-row"><span class="bar-label">'+h(label)+'</span><div class="bar-track"><div class="bar-fill" style="width:'+w+'%;background:'+col+'"></div></div><span class="bar-val">'+(valTxt||val)+'</span></div>'; }
function dropzone(kind){ return '<div class="drop" id="dz-'+kind+'"><svg class="ico" viewBox="0 0 24 24" width="26" height="26" style="color:var(--brand)"><path d="M12 16V4m0 0 4 4m-4-4-4 4"/><path d="M4 16v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/></svg><div style="font-weight:600">Arrastre su archivo aquí o haga clic</div><div class="dim" style="font-size:.78rem;margin-top:4px">.xlsx · .xls · .csv</div><input type="file" id="f-'+kind+'" accept=".xlsx,.xls,.csv" style="display:none"></div>'; }
function chartOpts(indexed){ return {maintainAspectRatio:false,interaction:{mode:'index',intersect:false},scales:{y:{min:0,max:105,ticks:{callback:function(v){return v+'%';}},grid:{color:'rgba(41,53,75,.35)'}},x:{grid:{display:false}}},plugins:{legend:{position:'top',align:'end'},tooltip:indexed?{callbacks:{label:function(c){return c.dataset.label+': '+c.dataset._r[c.dataIndex];}}}:{}}}; }

// ===================== Filtro riesgos =====================
window.filterRisks=function(){ var q=(el('fq').value||'').toLowerCase(), n=el('fn').value, vis=0;
  document.querySelectorAll('#rtab tbody tr').forEach(function(tr){ var ok=(tr.dataset.b||'').indexOf(q)>=0 && (!n||tr.dataset.n===n); tr.style.display=ok?'':'none'; if(ok)vis++; });
  el('fc').textContent=vis+' riesgos';
};

// ===================== Modales =====================
function modal(html,wide){ var o=document.createElement('div'); o.className='overlay'; o.onclick=function(e){if(e.target===o)o.remove();}; o.innerHTML='<div class="modal'+(wide?' wide':'')+'">'+html+'</div>'; el('modals').appendChild(o); return o; }
window.closeModal=function(elm){ var o=elm.closest?elm.closest('.overlay'):elm; if(o)o.remove(); };

window.openRisk=function(id){ var r=state.riesgos.filter(function(x){return x.id===id;})[0]; if(!r)return; var v=V[r.vuln_id], a=A[r.asset_id], t=T[r.threat_id], trats=tratsDe(r);
  var html='<div class="modal-head"><div><div class="eyebrow">'+h(r.codigo)+' · Estado: '+h(r.estado)+'</div><h2 style="font-size:1.35rem;margin-top:4px">'+h(t.nombre)+'</h2></div><button class="x" onclick="closeModal(this)">×</button></div>';
  html+='<p class="muted" style="margin:0 0 12px">'+h(r.descripcion||('Riesgo sobre '+a.nombre))+'</p>';
  html+='<div class="row" style="gap:8px;margin-bottom:16px">'+(t.attack_id?'<span class="tag">MITRE ATT&CK '+h(t.attack_id)+' · '+h(t.attack_tactica)+'</span>':'')
    +(slaVencido(r)?'<span class="chip critico">SLA vencido · '+(-slaRestante(r))+' días de retraso</span>':(['Controlado','Aceptado','Cerrado'].indexOf(r.estado)>=0?'<span class="chip bajo">Dentro de SLA</span>':'<span class="chip medio">SLA: '+slaRestante(r)+' días restantes (meta '+slaDias(r)+'d)</span>'))+'</div>';
  html+='<div class="grid g3">'
    +'<div class="card" style="padding:16px"><div class="dim" style="font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px">Componentes</div><div class="stack" style="gap:8px"><div><span class="dim" style="font-size:.74rem">Activo</span><br><b>'+h(a.codigo)+'</b> · '+h(a.nombre)+'</div><div><span class="dim" style="font-size:.74rem">Vulnerabilidad</span><br>'+h(v.nombre)+'</div></div></div>'
    +'<div class="card center" style="padding:16px"><div class="dim" style="font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px">Inherente</div><div style="font-family:var(--fs-display);font-size:2.6rem;font-weight:800;line-height:1;color:'+nivel(inh(r)).col+'">'+inh(r)+'</div>'+chip(nivel(inh(r)))+'<div class="dim" style="font-size:.74rem;margin-top:6px">P '+r.probabilidad+' × I '+r.impacto+'</div></div>'
    +'<div class="card center" style="padding:16px"><div class="dim" style="font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px">Residual (Fase 4)</div><div style="font-family:var(--fs-display);font-size:2.6rem;font-weight:800;line-height:1;color:'+nivel(res(r)).col+'">'+res(r)+'</div>'+chip(nivel(res(r)))+'<div class="chip bajo" style="margin-top:6px">Reducción '+reduccion(r)+'%</div></div>'
  +'</div>';
  if(v.cvss_score!=null){ html+='<div class="card mt" style="border-color:rgba(76,130,247,.25)"><div class="card-title">Inteligencia de amenazas · '+h(v.cve_id||'')+'</div><div class="grid g4" style="margin-top:6px">'
    +'<div><div class="dim" style="font-size:.72rem">CVSS 3.1</div><div class="mono" style="font-size:1.3rem;font-weight:700;color:'+(v.cvss_score>=9?'#d63a3a':v.cvss_score>=7?'#e8590c':'#e0a800')+'">'+v.cvss_score+'</div><div class="dim" style="font-size:.72rem">'+cvssSev(v.cvss_score)+'</div></div>'
    +'<div><div class="dim" style="font-size:.72rem">EPSS</div><div class="mono" style="font-size:1.3rem;font-weight:700">'+epssPct(v)+'%</div></div>'
    +'<div><div class="dim" style="font-size:.72rem">CISA KEV</div><div style="margin-top:6px">'+(v.kev?'<span class="chip critico">Explotada</span>':'<span class="dim">No listada</span>')+'</div></div>'
    +'<div><div class="dim" style="font-size:.72rem">VPR</div><div class="mono" style="font-size:1.3rem;font-weight:700;color:#d63a3a">'+vpr(v)+'</div><div class="dim" style="font-size:.72rem">'+vprNivel(v)+'</div></div>'
  +'</div>'+(v.cvss_vector?'<div class="mono dim" style="font-size:.74rem;margin-top:10px">'+h(v.cvss_vector)+'</div>':'')+'</div>'; }
  html+='<div class="card mt"><div class="row between"><div class="card-title">Plan de tratamiento <span class="dim" style="font-weight:400;font-size:.8rem">Fase 3 · ISO/IEC 27002:2022</span></div><button class="btn sm primary" onclick="openTreatment('+r.id+')">+ Añadir</button></div>';
  if(trats.length){ html+='<div class="table-wrap" style="margin-top:12px"><table class="data"><thead><tr><th>Estrategia</th><th>Control ISO</th><th>Descripción / Responsable</th><th>Eficacia</th><th>Estado</th></tr></thead><tbody>';
    trats.forEach(function(t2){ var ct=t2.control_id?C[t2.control_id]:null; html+='<tr><td><span class="tag'+(['Mitigar','Evitar'].indexOf(t2.estrategia)>=0?' brand':'')+'">'+h(t2.estrategia)+'</span></td><td>'+(ct?'<span class="code">'+h(ct.codigo_iso)+'</span><br><span class="dim" style="font-size:.74rem">'+h(ct.nombre)+'</span>':'<span class="dim">—</span>')+'</td><td class="stack" style="gap:2px"><span>'+h(t2.descripcion||'')+'</span><span class="dim" style="font-size:.74rem">Responsable: '+h(t2.responsable||'—')+'</span></td><td class="mono">'+(t2.eficacia||0)+'%</td><td><span class="tag">'+h(t2.estado)+'</span></td></tr>'; });
    html+='</tbody></table></div><div class="dim" style="font-size:.78rem;margin-top:10px">Eficacia combinada de controles implementados: <b>'+Math.round(eficacia(r)*100)+'%</b>.</div>';
  } else {
    var recs=recomendarControles(r), proj=residualProyectado(r,recs), nvp=nivel(proj), redp=Math.round((inh(r)-proj)/inh(r)*100);
    html+='<div class="row between" style="margin:12px 0 10px"><div class="muted" style="font-size:.88rem">Este riesgo aún no tiene tratamiento. El sistema recomienda automáticamente:</div><button class="btn sm primary" onclick="applyAuto('+r.id+')">⚡ Aplicar mitigación automática</button></div>';
    html+='<div class="table-wrap"><table class="data"><thead><tr><th>Control ISO 27002:2022</th><th>Estrategia</th><th>Eficacia estimada</th></tr></thead><tbody>';
    recs.forEach(function(x){ html+='<tr><td><span class="code">'+x.codigo_iso+'</span> · '+h(x.nombre)+'</td><td><span class="tag brand">Mitigar</span></td><td class="mono">'+x.eficacia+'%</td></tr>'; });
    html+='</tbody></table></div>';
    html+='<div class="row" style="margin-top:12px;gap:10px;align-items:center"><span class="muted" style="font-size:.85rem">Riesgo residual proyectado si se implementan:</span><span class="chip '+nvp.c+'">'+proj+' · '+nvp.n+'</span><span class="chip bajo">−'+redp+'%</span></div>';
  }
  html+='</div>';
  modal(html,true);
};

function selOptions(arr,valKey,txtFn,sel){ return arr.map(function(x){return '<option value="'+x[valKey]+'"'+(sel==x[valKey]?' selected':'')+'>'+h(txtFn(x))+'</option>';}).join(''); }

window.openNewAsset=function(){
  var html='<div class="modal-head"><div><div class="eyebrow">Fase 1 — Valoración de activos</div><h2 style="font-size:1.3rem;margin-top:4px">Nuevo activo</h2></div><button class="x" onclick="closeModal(this)">×</button></div>';
  html+='<form onsubmit="return saveAsset(this)"><div class="form-grid">'
    +field('Código *','<input class="control mono" name="codigo" placeholder="ACT-007" required>')
    +field('Tipo','<select class="control" name="tipo">'+['Información','Software','Hardware','Servicio','Personal','Instalación'].map(function(t){return '<option>'+t+'</option>';}).join('')+'</select>')
    +'<div class="full">'+field('Nombre *','<input class="control" name="nombre" placeholder="Base de datos de clientes" required>')+'</div>'
    +'<div class="full">'+field('Descripción','<textarea class="control" name="descripcion"></textarea>')+'</div>'
    +field('Propietario','<input class="control" name="propietario" placeholder="Jefe de Datos">')
  +'</div><div class="card-title" style="margin-top:8px">Valoración CIA <span class="dim" style="font-weight:400;font-size:.8rem">(1 = Muy Bajo · 5 = Muy Alto)</span></div><div class="form-grid" style="grid-template-columns:1fr 1fr 1fr;margin-top:12px">'
    +field('<span class="tip" data-tip="Impacto si la información es divulgada a terceros no autorizados.">Confidencialidad</span>',scaleInput('c',3))
    +field('<span class="tip" data-tip="Impacto si la información es alterada o corrompida.">Integridad</span>',scaleInput('i',3))
    +field('<span class="tip" data-tip="Impacto si el activo deja de estar disponible.">Disponibilidad</span>',scaleInput('d',3))
  +'</div><div class="row" style="margin-top:20px;padding-top:16px;border-top:1px solid var(--border-soft)"><button class="btn primary" type="submit">Guardar activo</button><button class="btn ghost" type="button" onclick="closeModal(this)">Cancelar</button></div></form>';
  modal(html);
};
window.saveAsset=function(form){ var d=formData(form);
  if(!d.codigo||!d.nombre||d.nombre.length<3){ toast('Complete código y nombre (mín. 3 caracteres).','err'); return false; }
  if(state.activos.some(function(a){return a.codigo.toUpperCase()===d.codigo.toUpperCase();})){ toast('Ya existe un activo con ese código.','err'); return false; }
  state.activos.push({id:nextId(),codigo:d.codigo.toUpperCase(),nombre:d.nombre,descripcion:d.descripcion||'',tipo:d.tipo||'Información',propietario:d.propietario||'',c:+d.c||3,i:+d.i||3,d:+d.d||3});
  saveState(); closeModal(form); toast('Activo guardado.','ok'); go('activos'); return false;
};

window.openNewRisk=function(){
  if(!state.activos.length){ toast('Primero registre al menos un activo.','warn'); go('activos'); return; }
  var html='<div class="modal-head"><div><div class="eyebrow">Fase 2 — Identificación de riesgos</div><h2 style="font-size:1.3rem;margin-top:4px">Nuevo riesgo</h2></div><button class="x" onclick="closeModal(this)">×</button></div>';
  html+='<form onsubmit="return saveRisk(this)"><div class="form-grid">'
    +field('Código *','<input class="control mono" name="codigo" placeholder="R-013" required>')
    +field('Estado','<select class="control" name="estado">'+['Identificado','En Tratamiento','Controlado','Aceptado','Cerrado'].map(function(e){return '<option>'+e+'</option>';}).join('')+'</select>')
    +field('Activo afectado *','<select class="control" name="asset_id" onchange="suggestRisk()" required><option value="">— Seleccione —</option>'+selOptions(state.activos,'id',function(a){return a.codigo+' · '+a.nombre;})+'</select>')
    +field('Amenaza *','<select class="control" name="threat_id" onchange="suggestRisk()" required><option value="">— Seleccione —</option>'+selOptions(state.amenazas,'id',function(t){return t.nombre;})+'</select>')
    +field('Vulnerabilidad *','<select class="control" name="vuln_id" onchange="suggestRisk()" required><option value="">— Seleccione —</option>'+selOptions(state.vulnerabilidades,'id',function(v){return v.nombre;})+'</select>')
    +'<div class="full">'+field('Descripción','<textarea class="control" name="descripcion"></textarea>')+'</div>'
  +'</div><div class="card-title" style="margin-top:8px">Valoración del riesgo inherente</div><div class="card-sub">Se calcula automáticamente al elegir activo, amenaza y vulnerabilidad. Puede ajustarla manualmente.</div><div class="form-grid">'
    +field('Probabilidad',scaleInput('probabilidad',3))
    +field('Impacto',scaleInput('impacto',3))
  +'</div>'
  +'<div id="autoNote" class="hint" style="margin:2px 0 10px;display:none"></div>'
  +'<div class="card" id="inhPrev" style="background:var(--bg-2);padding:12px 16px;display:flex;align-items:center;justify-content:space-between;gap:12px"><span class="muted" style="font-size:.85rem">Riesgo inherente calculado</span><span id="inhPrevVal"></span></div>'
  +'<div class="row" style="margin-top:20px;padding-top:16px;border-top:1px solid var(--border-soft)"><button class="btn primary" type="submit">Guardar riesgo</button><button class="btn ghost" type="button" onclick="closeModal(this)">Cancelar</button></div></form>';
  modal(html);
  updateInhPreview();
};
function setScale(name,val){ var sc=document.querySelector('.scale[data-name="'+name+'"]'); if(!sc)return; var btns=sc.querySelectorAll('button'); btns.forEach(function(b,idx){ b.classList.toggle('on', idx+1===val); }); if(sc.nextElementSibling) sc.nextElementSibling.value=val; }
function getHidden(name){ var i=document.querySelector('input[name="'+name+'"]'); return i?+i.value:3; }
window.updateInhPreview=function(){ var el2=el('inhPrevVal'); if(!el2)return; var p=getHidden('probabilidad'),i=getHidden('impacto'),s=p*i,nv=nivel(s); el2.innerHTML='<span class="chip '+nv.c+'">'+s+' · '+nv.n+'</span> <span class="dim mono" style="font-size:.82rem">(P'+p+' × I'+i+')</span>'; };
window.suggestRisk=function(){ var a=A[getVal('asset_id')],t=T[getVal('threat_id')],v=V[getVal('vuln_id')];
  if(!(a&&t&&v)){ updateInhPreview(); return; }
  var s=sugerirValoracion(a,t,v); setScale('probabilidad',s.p); setScale('impacto',s.i);
  var note=el('autoNote'); if(note){ note.style.display='block'; note.innerHTML='⚡ <b>Valoración automática:</b> '+h(s.motivo)+'. Ajústela si lo requiere.'; }
  updateInhPreview();
};
function getVal(name){ var e=document.querySelector('[name="'+name+'"]'); return e&&e.value?+e.value:null; }
window.saveRisk=function(form){ var d=formData(form);
  if(!d.codigo||!d.asset_id||!d.threat_id||!d.vuln_id){ toast('Complete código, activo, amenaza y vulnerabilidad.','err'); return false; }
  if(state.riesgos.some(function(r){return r.codigo.toUpperCase()===d.codigo.toUpperCase();})){ toast('Ya existe un riesgo con ese código.','err'); return false; }
  state.riesgos.push({id:nextId(),codigo:d.codigo.toUpperCase(),asset_id:+d.asset_id,threat_id:+d.threat_id,vuln_id:+d.vuln_id,descripcion:d.descripcion||'',controles_existentes:'',probabilidad:+d.probabilidad||3,impacto:+d.impacto||3,estado:d.estado||'Identificado',dias_edad:0});
  saveState(); closeModal(form); toast('Riesgo creado.','ok'); go('riesgos'); return false;
};

window.openTreatment=function(rid){ var r=state.riesgos.filter(function(x){return x.id===rid;})[0]; if(!r)return;
  var html='<div class="modal-head"><div><div class="eyebrow">Fase 3 — Tratamiento del riesgo</div><h2 style="font-size:1.3rem;margin-top:4px">Definir tratamiento · '+h(r.codigo)+'</h2></div><button class="x" onclick="closeModal(this)">×</button></div>';
  html+='<form onsubmit="return saveTreatment(this,'+rid+')"><div class="form-grid">'
    +field('Estrategia *','<select class="control" name="estrategia">'+['Mitigar','Transferir','Aceptar','Evitar'].map(function(e){return '<option>'+e+'</option>';}).join('')+'</select>')
    +field('Control ISO 27002:2022','<select class="control" name="control_id"><option value="">— Sin control específico —</option>'+selOptions(state.controles,'id',function(c){return c.codigo_iso+' · '+c.nombre;})+'</select>')
    +'<div class="full">'+field('Control propuesto / plan de acción','<textarea class="control" name="descripcion" placeholder="Describa el control a implementar..."></textarea>')+'</div>'
    +field('Responsable','<input class="control" name="responsable" placeholder="Administrador de TI">')
    +field('<span class="tip" data-tip="Solo los controles Implementado o Verificado reducen el riesgo residual.">Estado del control</span>','<select class="control" name="estado">'+['Propuesto','En Implementación','Implementado','Verificado'].map(function(e){return '<option>'+e+'</option>';}).join('')+'</select>')
    +'<div class="full">'+field('Eficacia estimada (%) — 0 a 90','<input class="control" type="number" name="eficacia" min="0" max="90" value="50">')+'</div>'
  +'</div><div class="row" style="margin-top:20px;padding-top:16px;border-top:1px solid var(--border-soft)"><button class="btn primary" type="submit">Guardar tratamiento</button><button class="btn ghost" type="button" onclick="closeModal(this)">Cancelar</button></div></form>';
  modal(html);
};
window.saveTreatment=function(form,rid){ var d=formData(form); var ef=Math.max(0,Math.min(90,+d.eficacia||0)); var r=state.riesgos.filter(function(x){return x.id===rid;})[0];
  state.tratamientos.push({risk_id:rid,control_id:d.control_id?+d.control_id:null,estrategia:d.estrategia,descripcion:d.descripcion||'',responsable:d.responsable||'',eficacia:d.estrategia==='Aceptar'?0:ef,estado:d.estado||'Propuesto'});
  if(d.estrategia==='Aceptar') r.estado='Aceptado'; else if(r.estado==='Identificado') r.estado='En Tratamiento';
  saveState(); closeModal(form); toast('Tratamiento registrado. Riesgo residual recalculado.','ok'); openRisk(rid); return false;
};

// ===================== Enriquecimiento (demo local) =====================
window.enrich=function(id){ var v=state.vulnerabilidades.filter(function(x){return x.id===id;})[0]; var cve=(el('cve'+id).value||'').trim().toUpperCase();
  if(!/^CVE-\d{4}-\d{4,7}$/.test(cve)){ toast('Formato inválido. Use CVE-AAAA-NNNN.','err'); return; }
  var d=CVE_DB[cve];
  v.cve_id=cve;
  if(d){ v.cvss_score=d.cvss; v.cvss_vector=d.vec; v.epss_score=d.epss; v.kev=d.kev; v.kev_fecha=d.kevf; if(d.desc) v.descripcion=d.desc;
    saveState(); toast(cve+' enriquecido — CVSS '+d.cvss+' · EPSS '+Math.round(d.epss*1000)/10+'% · '+(d.kev?'KEV ✔':'no-KEV')+' · VPR '+vpr(v),'ok');
  } else { saveState(); toast(cve+' registrado. No está en el catálogo local de demostración (la versión completa lo consulta en NVD/EPSS/CISA en vivo).','warn'); }
  go('inteligencia');
};

// ===================== Importación Excel/CSV =====================
var COLS={ activos:['codigo','nombre','tipo','propietario','confidencialidad','integridad','disponibilidad','descripcion'],
           riesgos:['codigo','activo_codigo','amenaza','vulnerabilidad','probabilidad','impacto','estado','descripcion'] };
var SAMPLE={ activos:[['ACT-101','Servidor de aplicaciones','Hardware','Administrador TI',4,4,5,'Servidor productivo principal']],
             riesgos:[['R-101','ACT-101','Ransomware','Software sin parches',4,5,'Identificado','Cifrado malicioso del servidor']] };

function bindDrop(kind){ var dz=el('dz-'+kind), inp=el('f-'+kind); if(!dz)return;
  dz.onclick=function(){inp.click();};
  dz.ondragover=function(e){e.preventDefault();dz.classList.add('hover');};
  dz.ondragleave=function(){dz.classList.remove('hover');};
  dz.ondrop=function(e){e.preventDefault();dz.classList.remove('hover');if(e.dataTransfer.files[0])readFile(e.dataTransfer.files[0],kind);};
  inp.onchange=function(){if(inp.files[0])readFile(inp.files[0],kind);};
}
function readFile(file,kind){ var fr=new FileReader(); var isCsv=/\.csv$/i.test(file.name);
  fr.onload=function(e){ try{ var wb=isCsv?XLSX.read(e.target.result,{type:'string'}):XLSX.read(new Uint8Array(e.target.result),{type:'array'});
    var rows=XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]],{defval:''}); preview(kind,rows);
  }catch(err){ toast('No se pudo leer el archivo: '+err.message,'err'); } };
  if(isCsv) fr.readAsText(file); else fr.readAsArrayBuffer(file);
}
function preview(kind,rows){ if(!rows.length){ toast('El archivo no contiene filas.','warn'); return; }
  var valid=[],errs=0;
  rows.forEach(function(row){ var r=normalizeRow(kind,row); if(r.__err) errs++; else valid.push(r); });
  var html='<div class="card mt"><div class="row between"><div class="card-title">Vista previa — '+kind+'</div><div class="row"><span class="dim" style="font-size:.82rem">'+valid.length+' válidas'+(errs?' · '+errs+' con error':'')+'</span><button class="btn sm primary" onclick="applyImport(\''+kind+'\')">Importar '+valid.length+' filas</button></div></div>';
  html+='<div class="table-wrap"><table class="data"><thead><tr>'+COLS[kind].map(function(c){return '<th>'+c+'</th>';}).join('')+'<th></th></tr></thead><tbody>';
  rows.slice(0,50).forEach(function(row){ var r=normalizeRow(kind,row); html+='<tr>'+COLS[kind].map(function(c){return '<td>'+h(row[c]!=null?row[c]:'')+'</td>';}).join('')+'<td>'+(r.__err?'<span class="chip critico">'+h(r.__err)+'</span>':'<span class="chip bajo">OK</span>')+'</td></tr>'; });
  html+='</tbody></table></div>'+(rows.length>50?'<div class="dim" style="font-size:.78rem;margin-top:8px">Mostrando 50 de '+rows.length+' filas.</div>':'')+'</div>';
  el('preview').innerHTML=html; window.__pending={kind:kind,rows:valid}; el('preview').scrollIntoView({behavior:'smooth'});
}
function normalizeRow(kind,row){
  var g=function(k){ return row[k]!=null?String(row[k]).trim():''; };
  if(kind==='activos'){ var codigo=g('codigo').toUpperCase(),nombre=g('nombre');
    if(!codigo||nombre.length<3) return {__err:'código/nombre'};
    var c=+g('confidencialidad')||3,i=+g('integridad')||3,d=+g('disponibilidad')||3;
    if([c,i,d].some(function(x){return x<1||x>5;})) return {__err:'CIA 1–5'};
    return {codigo:codigo,nombre:nombre,tipo:g('tipo')||'Información',propietario:g('propietario'),c:c,i:i,d:d,descripcion:g('descripcion')};
  } else { var cod=g('codigo').toUpperCase(),ac=g('activo_codigo').toUpperCase();
    if(!cod||!ac) return {__err:'código/activo'};
    var p=+g('probabilidad')||3,im=+g('impacto')||3;
    if(p<1||p>5||im<1||im>5) return {__err:'P/I 1–5'};
    var a=state.activos.filter(function(x){return x.codigo.toUpperCase()===ac;})[0];
    if(!a) return {__err:'activo inexistente'};
    return {codigo:cod,activo_codigo:ac,amenaza:g('amenaza'),vulnerabilidad:g('vulnerabilidad'),probabilidad:p,impacto:im,estado:g('estado')||'Identificado',descripcion:g('descripcion')};
  }
}
window.applyImport=function(kind){ var p=window.__pending; if(!p||p.kind!==kind){ return; } var added=0,skip=0;
  if(kind==='activos'){ p.rows.forEach(function(r){ if(state.activos.some(function(a){return a.codigo.toUpperCase()===r.codigo;})){skip++;return;} state.activos.push({id:nextId(),codigo:r.codigo,nombre:r.nombre,descripcion:r.descripcion,tipo:r.tipo,propietario:r.propietario,c:r.c,i:r.i,d:r.d}); added++; }); }
  else { p.rows.forEach(function(r){ if(state.riesgos.some(function(x){return x.codigo.toUpperCase()===r.codigo;})){skip++;return;}
    var a=state.activos.filter(function(x){return x.codigo.toUpperCase()===r.activo_codigo;})[0]; if(!a){skip++;return;}
    var t=state.amenazas.filter(function(x){return x.nombre.toLowerCase()===r.amenaza.toLowerCase();})[0]; if(!t&&r.amenaza){t={id:nextId(),nombre:r.amenaza,categoria:'Importada',descripcion:'',attack_id:null,attack_tactica:null};state.amenazas.push(t);}
    var v=state.vulnerabilidades.filter(function(x){return x.nombre.toLowerCase()===r.vulnerabilidad.toLowerCase();})[0]; if(!v&&r.vulnerabilidad){v={id:nextId(),nombre:r.vulnerabilidad,categoria:'Importada',descripcion:'',cve_id:null,cvss_score:null,cvss_vector:null,epss_score:null,epss_percentile:null,kev:false,kev_fecha:null};state.vulnerabilidades.push(v);}
    if(!t||!v){skip++;return;}
    state.riesgos.push({id:nextId(),codigo:r.codigo,asset_id:a.id,threat_id:t.id,vuln_id:v.id,descripcion:r.descripcion,controles_existentes:'',probabilidad:r.probabilidad,impacto:r.impacto,estado:r.estado,dias_edad:0}); added++;
  }); }
  saveState(); reindex(); el('preview').innerHTML=''; window.__pending=null;
  toast(added+' '+kind+' importados'+(skip?' · '+skip+' omitidos':'')+'.','ok');
  go(kind);
};

// ===================== Plantillas =====================
function tplRows(kind){ return [COLS[kind]].concat(SAMPLE[kind]); }
window.tpl=function(kind){ var ws=XLSX.utils.aoa_to_sheet(tplRows(kind)); var wb=XLSX.utils.book_new(); XLSX.utils.book_append_sheet(wb,ws,kind); XLSX.writeFile(wb,'plantilla_'+kind+'.xlsx'); toast('Plantilla .xlsx descargada.','ok'); };
window.tplCsv=function(kind){ var rows=tplRows(kind), csv=rows.map(function(r){return r.map(function(c){return '"'+String(c).replace(/"/g,'""')+'"';}).join(',');}).join('\n');
  var b=new Blob([csv],{type:'text/csv;charset=utf-8'}); var a=document.createElement('a'); a.href=URL.createObjectURL(b); a.download='plantilla_'+kind+'.csv'; a.click(); toast('Plantilla .csv descargada.','ok'); };

// ===================== Form helpers =====================
function field(label,inner){ return '<div class="field"><label>'+label+'</label>'+inner+'</div>'; }
function scaleInput(name,def){ var h5=''; for(var i=1;i<=5;i++) h5+='<button type="button" class="'+(i===def?'on':'')+'" onclick="pickScale(this,'+i+')">'+i+'</button>'; return '<div class="scale" data-name="'+name+'">'+h5+'</div><input type="hidden" name="'+name+'" value="'+def+'">'; }
window.pickScale=function(btn,val){ var sc=btn.parentNode; sc.querySelectorAll('button').forEach(function(b){b.classList.remove('on');}); btn.classList.add('on'); sc.nextElementSibling.value=val; if(window.updateInhPreview) window.updateInhPreview(); };
function formData(form){ var d={}; Array.prototype.forEach.call(form.elements,function(e){ if(e.name) d[e.name]=e.value; }); return d; }

// ===================== Init =====================
function buildShell(){
  var items=[
    ['','Panel de monitoreo','panel','<path d="M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z"/>'],
  ];
  var nav='<div class="brand" onclick="go(\'panel\')"><div class="brand-mark"><span></span></div><div class="brand-name">CyberRisk 360<small>Gestión de Riesgos</small></div></div>';
  nav+='<button class="nav-item" data-view="panel" onclick="go(\'panel\')"><svg class="ico" viewBox="0 0 24 24"><path d="M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z"/></svg>Panel de monitoreo</button>';
  nav+='<div class="nav-label">Metodología GRC-360</div>';
  [['activos','1','Valoración de activos'],['riesgos','2','Identificación de riesgos'],['tratamiento','3','Tratamiento (ISO 27002)'],['residual','4','Riesgo residual'],['comunicacion','5','Comunicación y consulta'],['panel','6','Monitoreo y supervisión']].forEach(function(x){
    nav+='<button class="nav-item" data-view="'+x[0]+'" onclick="go(\''+x[0]+'\')"><span class="phase-num">'+x[1]+'</span>'+x[2]+'</button>';
  });
  nav+='<div class="nav-label">Inteligencia y cumplimiento</div>';
  nav+='<button class="nav-item" data-view="inteligencia" onclick="go(\'inteligencia\')"><svg class="ico" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>Inteligencia de amenazas</button>';
  nav+='<button class="nav-item" data-view="cumplimiento" onclick="go(\'cumplimiento\')"><svg class="ico" viewBox="0 0 24 24"><path d="M12 2 4 6v6c0 4 3 7 8 9 5-2 8-5 8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>Cumplimiento</button>';
  nav+='<div class="nav-label">Herramientas</div>';
  nav+='<button class="nav-item" data-view="importar" onclick="go(\'importar\')"><svg class="ico" viewBox="0 0 24 24"><path d="M12 16V4m0 0 4 4m-4-4-4 4"/><path d="M4 16v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/></svg>Importar Excel/CSV</button>';
  nav+='<button class="nav-item" onclick="resetDemo()"><svg class="ico" viewBox="0 0 24 24"><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/></svg>Restablecer demo</button>';

  document.body.innerHTML=''
    +'<div class="app"><aside class="sidebar" id="sidebar">'+nav+'</aside>'
    +'<div class="main"><div class="topbar"><button class="menu-btn" onclick="document.getElementById(\'sidebar\').classList.toggle(\'open\')">☰ Menú</button>'
      +'<div class="row" style="margin-left:auto"><div class="stack" style="gap:0;text-align:right"><b style="font-size:.82rem">'+h(state.meta.organizacion)+'</b><span class="dim" style="font-size:.72rem">Programa GRC · Demo</span></div><div class="brand-mark" style="width:32px;height:32px"><span style="width:12px;height:12px"></span></div></div></div>'
      +'<div class="content" id="content"></div></div></div>'
    +'<div id="modals"></div><div class="toasts" id="toasts"></div>';
}
function chartDefaults(){ if(!window.Chart)return; Chart.defaults.font.family="ui-sans-serif,system-ui,sans-serif"; Chart.defaults.font.size=12; Chart.defaults.color='#93a1b8'; Chart.defaults.borderColor='rgba(41,53,75,.5)'; Chart.defaults.plugins.legend.labels.usePointStyle=true; Chart.defaults.plugins.legend.labels.boxWidth=8; Chart.defaults.plugins.legend.labels.padding=14; }

function boot(){ loadState(); reindex(); chartDefaults(); buildShell(); var hv=(location.hash||'').slice(1);
  var mr=hv.match(/^riesgo(\d+)$/); if(mr){ go('riesgos'); openRisk(+mr[1]); return; }
  go(VIEWS[hv]?hv:'panel'); }
if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',boot); else boot();
})();
