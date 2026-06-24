/** Stand-in for pages not yet ported from the Yew app (P3 of the migration). */
export function Placeholder({ title }: { title: string }) {
  return (
    <div className="mx-auto max-w-4xl p-6">
      <h1 className="text-2xl font-bold">{title}</h1>
      <div className="mt-4 rounded-md border bg-card p-10 text-center text-muted-foreground">
        This page hasn't been migrated to the new UI yet.
      </div>
    </div>
  );
}
