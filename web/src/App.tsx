import React from 'react';
import { AppShell } from './components/AppShell';
import { SessionProvider, useSession } from './context/SessionContext';
import { canAccessTab } from './lib/rbac';
import { AdminView } from './views/AdminView';
import { CoDevView } from './views/CoDevView';
import { LibrarianView } from './views/LibrarianView';
import { LoginView } from './views/LoginView';
import { PurchasingView } from './views/PurchasingView';

const PortalRouter: React.FC = () => {
  const { principal, loading, activeTab } = useSession();

  if (loading) {
    return (
      <div className="login-page">
        <div className="card">Establishing TLS 1.3 tenant session...</div>
      </div>
    );
  }

  if (!principal) {
    return <LoginView />;
  }

  const effectiveTab = canAccessTab(principal, activeTab) ? activeTab : 'codev';

  return (
    <AppShell>
      {effectiveTab === 'codev' && <CoDevView />}
      {effectiveTab === 'librarian' && <LibrarianView />}
      {effectiveTab === 'purchasing' && <PurchasingView />}
      {effectiveTab === 'admin' && <AdminView />}
    </AppShell>
  );
};

export const App: React.FC = () => (
  <SessionProvider>
    <PortalRouter />
  </SessionProvider>
);

export default App;
