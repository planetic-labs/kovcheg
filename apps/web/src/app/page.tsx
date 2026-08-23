import { connection } from 'next/server';

export default async function FoundationPage() {
  await connection();

  return (
    <main>
      <h1>Kovcheg</h1>
      <p>Alpha-0 technical foundation</p>
    </main>
  );
}
