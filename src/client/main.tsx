import './theme-init';
import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import '@fontsource/geist/latin-400.css';
import '@fontsource/geist/latin-500.css';
import '@fontsource/geist/latin-600.css';
import '@fontsource/geist/latin-700.css';
import './styles.css';

const root = document.getElementById('root');
if (!root) throw new Error('Lockit could not find its application root.');

createRoot(root).render(<App />);
