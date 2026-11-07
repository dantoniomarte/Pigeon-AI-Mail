import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import './i18n';
import './styles/variables.css';
import './styles/base.css';
import './styles/components.css';
import './styles/animations.css';
import './styles/responsive.css';

import App from './App';

const container = document.getElementById('root');

if (container === null) {
  throw new Error('Pigeon Mail: missing #root container');
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
