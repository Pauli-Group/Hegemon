import { Link } from 'react-router-dom';
import { PageShell } from '../components/PageShell';

export function NotFoundPage() {
  return (
    <PageShell title="Page not found" intro="Choose an action catalog entry or use quickstart to resume guided flows.">
      <p>
        Return to the <Link to="/">catalog</Link> or jump to the <Link to="/quickstart">quickstart summary</Link>.
      </p>
    </PageShell>
  );
}
