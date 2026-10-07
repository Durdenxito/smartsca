import { useEffect, useState } from 'react';
import NewAnalysisPage from './pages/NewAnalysisPage';
import AnalysisStatusPage from './pages/AnalysisStatusPage';
import ComponentsPage from './pages/ComponentsPage';
import GraphPage from './pages/GraphPage';
import FindingsPage from './pages/FindingsPage';
import AnalysisSummaryPage from './pages/AnalysisSummaryPage';
import HistoryPage from './pages/HistoryPage';
import './styles.css';

export default function App() {
  const [hash, setHash] = useState(window.location.hash);
  useEffect(() => {
    const navigate = () => setHash(window.location.hash);
    window.addEventListener('hashchange', navigate);
    return () => window.removeEventListener('hashchange', navigate);
  }, []);
  const route = /^#analysis\/([^/?]+)(?:\/(components|graph|findings|summary))?(?:\?(.*))?$/.exec(hash);
  return <>
    <header><a href="#" aria-label="SmartSCA, inicio">SmartSCA</a><span>Java / Maven</span><a href="#history">Historial</a></header>
    <main>{/^#history(?:\?|$)/.test(hash) ? <HistoryPage key={hash} query={hash.split('?').slice(1).join('?')} /> : route ? route[2] === 'summary' ? <AnalysisSummaryPage key={route[1]} id={route[1]} />
      : route[2] === 'findings' ? <FindingsPage key={`${route[1]}/${route[3] ?? ''}`} id={route[1]} initialPurl={new URLSearchParams(route[3]).get('component') ?? ''} />
      : route[2] === 'graph' ? <GraphPage key={`${route[1]}/${route[3] ?? ''}`} id={route[1]} initialPurl={new URLSearchParams(route[3]).get('component') ?? ''} />
      : route[2] === 'components' ? <ComponentsPage key={route[1]} id={route[1]} /> : <AnalysisStatusPage key={route[1]} id={route[1]} /> : <NewAnalysisPage />}</main>
  </>;
}
