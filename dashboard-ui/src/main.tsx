import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.tsx';
import './design/global.css';
import { ToastProvider } from './components/ToastProvider.tsx';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ToastProvider>
      <App />
    </ToastProvider>
  </React.StrictMode>
);
