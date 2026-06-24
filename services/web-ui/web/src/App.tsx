import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Navigate, Route, Routes } from "react-router-dom";

import { EstPage } from "@/pages/est";

const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false, staleTime: 10_000 } },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Routes>
        <Route path="/est" element={<EstPage />} />
        {/* POC: only the EST page is ported. Other routes follow in P3. */}
        <Route path="*" element={<Navigate to="/est" replace />} />
      </Routes>
    </QueryClientProvider>
  );
}
