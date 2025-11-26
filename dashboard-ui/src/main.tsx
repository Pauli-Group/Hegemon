import React from 'react';
import ReactDOM from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import App from './App.tsx';
import './design/global.css';
import { ToastProvider } from './components/ToastProvider.tsx';
import { NodeConnectionProvider } from './providers/NodeConnectionProvider.tsx';
import { SubstrateApiProvider } from './providers/SubstrateApiProvider.tsx';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      staleTime: 1000,
    },
  },
});

// Check if we should use Substrate WebSocket or legacy HTTP
const useSubstrate = import.meta.env.VITE_USE_SUBSTRATE !== 'false';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      {useSubstrate ? (
        <SubstrateApiProvider>
          <NodeConnectionProvider>
            <ToastProvider>
              <App />
            </ToastProvider>
          </NodeConnectionProvider>
        </SubstrateApiProvider>
      ) : (
        <NodeConnectionProvider>
          <ToastProvider>
            <App />
          </ToastProvider>
        </NodeConnectionProvider>
      )}
    </QueryClientProvider>
  </React.StrictMode>
);
