import { BrowserRouter, NavLink, Route, Routes } from 'react-router-dom';
import { ActionCatalogPage } from './pages/ActionCatalogPage';
import { ActionRunPage } from './pages/ActionRunPage';
import { QuickstartPage } from './pages/QuickstartPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { WalletPage } from './pages/WalletPage';
import { MiningPage } from './pages/MiningPage';
import { NetworkPage } from './pages/NetworkPage';
import { NodePage } from './pages/NodePage';
import { useNodeMetrics } from './hooks/useNodeData';
import { ConnectionBadge } from './components/ConnectionBadge';
import styles from './App.module.css';

function App() {
  const nodeMetrics = useNodeMetrics();
  return (
    <BrowserRouter>
      <div className="app-shell">
        <header className={styles.navbar}>
          <div className={styles.brandRow}>
            <span className={styles.brand}>Ops dashboard</span>
            <ConnectionBadge
              source={nodeMetrics.data?.source ?? 'mock'}
              error={nodeMetrics.data?.error}
              label="Node metrics feed"
            />
          </div>
          <nav className={styles.navLinks}>
            <NavLink to="/" end>
              Catalog
            </NavLink>
            <NavLink to="/quickstart">Quickstart</NavLink>
            <NavLink to="/wallet">Wallet</NavLink>
            <NavLink to="/mining">Mining</NavLink>
            <NavLink to="/node">Node</NavLink>
            <NavLink to="/network">Network</NavLink>
          </nav>
        </header>
        <Routes>
          <Route path="/" element={<ActionCatalogPage />} />
          <Route path="/quickstart" element={<QuickstartPage />} />
          <Route path="/wallet" element={<WalletPage />} />
          <Route path="/mining" element={<MiningPage />} />
          <Route path="/node" element={<NodePage />} />
          <Route path="/network" element={<NetworkPage />} />
          <Route path="/actions/:slug" element={<ActionRunPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;
