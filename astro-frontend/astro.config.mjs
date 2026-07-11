import { defineConfig } from 'astro/config';
import node from '@astrojs/node';

// SSR: cada página se renderiza en el servidor obteniendo los datos desde la
// API Flask en tiempo de solicitud. Chart.js se hidrata como isla en el cliente.
export default defineConfig({
  output: 'server',
  adapter: node({ mode: 'standalone' }),
  server: { port: 4321, host: true },
});
