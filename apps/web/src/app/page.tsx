import { connection } from 'next/server';

import { ClientShell } from './client-shell';

export default async function HomePage() {
  await connection();

  return <ClientShell />;
}
