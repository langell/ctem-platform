import type { ReactNode } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { Layout } from './ui/Layout';
import { LoginPage } from './pages/LoginPage';
import { AssetsPage } from './pages/AssetsPage';
import { FindingsPage } from './pages/FindingsPage';
import { FindingDetailPage } from './pages/FindingDetailPage';
import { ScanPage } from './pages/ScanPage';
import { PoliciesPage } from './pages/PoliciesPage';
import { tokenStore } from './api/client';

function RequireToken({ children }: { children: ReactNode }) {
  if (!tokenStore().get()) return <Navigate to="/login" replace />;
  return children;
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireToken>
            <Layout />
          </RequireToken>
        }
      >
        <Route path="/assets" element={<AssetsPage />} />
        <Route path="/findings" element={<FindingsPage />} />
        <Route path="/findings/:id" element={<FindingDetailPage />} />
        <Route path="/scans" element={<ScanPage />} />
        <Route path="/policies" element={<PoliciesPage />} />
        <Route path="/" element={<Navigate to="/findings" replace />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
