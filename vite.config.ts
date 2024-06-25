import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import { viteStaticCopy } from 'vite-plugin-static-copy'
import externalize from 'vite-plugin-externalize-dependencies';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    externalize({ externals: ['/nimiq/web/index.js'] }),
    viteStaticCopy({
      targets: [
        { src: './node_modules/@nimiq/core/(lib|web)', dest: 'nimiq' },
      ],
    }),
    svelte(),
  ],
  build: {
    rollupOptions: {
      external: ['/nimiq/web/index.js'],
    },
  },

})
