import React from 'react';
import { AppShell } from './components/AppShell';
import { Mark } from './components/ui';
import { SessionProvider, useSession } from './context/SessionContext';
import { canAccessTab } from './lib/rbac';
import { AdminView } from './views/AdminView';
import { CoDevView } from './views/CoDevView';
import { LibrarianView } from './views/LibrarianView';
import { LoginView } from './views/LoginView';
import { OverviewView } from './views/OverviewView';
import { PurchasingView } from './views/PurchasingView';

const PortalRouter: React.FC = () => {
  const { principal, loading, activeTab } = useSession();

  if (loading) {
    return (
      <div className="boot" role="status">
        <div className="boot-inner">
          <Mark size={22} />
          <span>Checking session…</span>
        </div>
      </div>
    );
  }

  if (!principal) {
    return <LoginView />;
  }

  const effectiveTab = canAccessTab(principal, activeTab) ? activeTab : 'overview';

  return (
    <AppShell>
      {effectiveTab === 'overview' && <OverviewView />}
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
