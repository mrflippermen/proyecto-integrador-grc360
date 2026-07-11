# Cliente estático (GitHub Pages)

Código fuente de la aplicación cliente de una sola página servida en
`../index.html`. El HTML final se genera embebiendo estos archivos + Chart.js +
SheetJS:

- `app.js` — motor SPA: lógica GRC-360, valoración y mitigación automática, importación Excel/CSV, gráficos y modales.
- `styles.css` — sistema de diseño "Consola de Operaciones de Riesgo".
- `seed_data.json` — caso de ejemplo (FinTech Andina S.A.).

La app es 100% cliente (sin backend): los datos se guardan en `localStorage`.
