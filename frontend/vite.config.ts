import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const backendTarget = env.VITE_BACKEND_URL || process.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';

  return {
    plugins: [react()],
    resolve: {
      alias: [
        { find: '@', replacement: path.resolve(__dirname, './src') },
        {
          find: /^three$/,
          replacement: path.resolve(
            __dirname,
            './node_modules/3d-force-graph/node_modules/three/build/three.module.js'
          ),
        },
        {
          find: /^three\/webgpu$/,
          replacement: path.resolve(
            __dirname,
            './node_modules/3d-force-graph/node_modules/three/build/three.webgpu.js'
          ),
        },
        {
          find: /^three\/tsl$/,
          replacement: path.resolve(
            __dirname,
            './node_modules/3d-force-graph/node_modules/three/build/three.tsl.js'
          ),
        },
        {
          find: /^three\/addons\/(.*)$/,
          replacement: `${path.resolve(
            __dirname,
            './node_modules/3d-force-graph/node_modules/three/examples/jsm'
          )}/$1`,
        },
      ],
      dedupe: ['three'],
    },
    server: {
      port: 5173,
      host: true,
      proxy: {
        '/api': {
          target: backendTarget,
          changeOrigin: true,
        },
        '/health': {
          target: backendTarget,
          changeOrigin: true,
        },
      },
    },
  };
});

