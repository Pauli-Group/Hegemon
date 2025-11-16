import { BrowserRouter, NavLink, Route, Routes } from 'react-router-dom';
import { ActionCatalogPage } from './pages/ActionCatalogPage';
import { ActionRunPage } from './pages/ActionRunPage';
import { QuickstartPage } from './pages/QuickstartPage';
import { NotFoundPage } from './pages/NotFoundPage';
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
          </nav>
        </header>
        <Routes>
          <Route path="/" element={<ActionCatalogPage />} />
          <Route path="/quickstart" element={<QuickstartPage />} />
          <Route path="/actions/:slug" element={<ActionRunPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;
