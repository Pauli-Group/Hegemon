import React from 'react';
import ReactDOM from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import App from './App.tsx';
import './design/global.css';
import { ToastProvider } from './components/ToastProvider.tsx';
import { NodeConnectionProvider } from './providers/NodeConnectionProvider.tsx';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      staleTime: 1000,
    },
  },
});

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <NodeConnectionProvider>
        <ToastProvider>
          <App />
        </ToastProvider>
      </NodeConnectionProvider>
    </QueryClientProvider>
  </React.StrictMode>
);
