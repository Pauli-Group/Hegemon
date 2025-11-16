import { BrowserRouter, NavLink, Route, Routes } from 'react-router-dom';
import { ActionCatalogPage } from './pages/ActionCatalogPage';
import { ActionRunPage } from './pages/ActionRunPage';
import { QuickstartPage } from './pages/QuickstartPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { WalletPage } from './pages/WalletPage';
import { MiningPage } from './pages/MiningPage';
import { NetworkPage } from './pages/NetworkPage';
import styles from './App.module.css';

function App() {
  return (
    <BrowserRouter>
      <div className="app-shell">
        <header className={styles.navbar}>
          <span className={styles.brand}>Ops dashboard</span>
          <nav className={styles.navLinks}>
            <NavLink to="/" end>
              Catalog
            </NavLink>
            <NavLink to="/quickstart">Quickstart</NavLink>
            <NavLink to="/wallet">Wallet</NavLink>
            <NavLink to="/mining">Mining</NavLink>
            <NavLink to="/network">Network</NavLink>
          </nav>
        </header>
        <Routes>
          <Route path="/" element={<ActionCatalogPage />} />
          <Route path="/quickstart" element={<QuickstartPage />} />
          <Route path="/wallet" element={<WalletPage />} />
          <Route path="/mining" element={<MiningPage />} />
          <Route path="/network" element={<NetworkPage />} />
          <Route path="/actions/:slug" element={<ActionRunPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;
