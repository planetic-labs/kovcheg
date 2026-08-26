import type { MetadataRoute } from 'next';

export default function manifest(): MetadataRoute.Manifest {
  return {
    background_color: '#f2efe8',
    description: 'Минимальный PWA-клиент Ковчега',
    display: 'standalone',
    icons: [
      {
        purpose: 'maskable',
        sizes: 'any',
        src: '/pwa-icon.svg',
        type: 'image/svg+xml',
      },
    ],
    id: '/',
    lang: 'ru',
    name: 'Ковчег',
    orientation: 'any',
    scope: '/',
    short_name: 'Ковчег',
    start_url: '/',
    theme_color: '#1b443b',
  };
}
