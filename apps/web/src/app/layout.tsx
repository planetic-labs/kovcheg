import type { Metadata, Viewport } from 'next';
import type { ReactNode } from 'react';

import './globals.css';

export const metadata: Metadata = {
  applicationName: 'Ковчег',
  description: 'Минимальный PWA-клиент Ковчега',
  icons: { icon: '/pwa-icon.svg' },
  manifest: '/manifest.webmanifest',
  title: 'Ковчег',
};

export const viewport: Viewport = {
  colorScheme: 'light',
  themeColor: '#1b443b',
  width: 'device-width',
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="ru">
      <body>{children}</body>
    </html>
  );
}
