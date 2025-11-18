import type { TransferRecord } from '../types/node';
import { formatCoinsFromAtomic } from '../utils/amounts';
import styles from './TransactionTable.module.css';

interface TransactionTableProps {
  records: TransferRecord[];
}

export function TransactionTable({ records }: TransactionTableProps) {
  if (!records.length) {
    return <p className={styles.empty}>No transactions yet.</p>;
  }
  return (
    <table className={styles.table}>
      <thead>
        <tr>
          <th>Tx ID</th>
          <th>Direction</th>
          <th>Address</th>
          <th>Amount</th>
          <th>Status</th>
          <th>Confirmations</th>
          <th>Timestamp</th>
        </tr>
      </thead>
      <tbody>
        {records.map((record) => (
          <tr key={record.id}>
            <td className={styles.txId}>
              <code>{record.tx_id.slice(0, 18)}{record.tx_id.length > 18 ? '…' : ''}</code>
            </td>
            <td>
              <span className={`${styles.badge} ${record.direction === 'incoming' ? styles.incoming : styles.outgoing}`}>
                {record.direction}
              </span>
            </td>
            <td className={styles.address}>{record.address}</td>
            <td>{formatCoinsFromAtomic(record.amount)} HGN</td>
            <td>{record.status}</td>
            <td>{record.confirmations}</td>
            <td>{new Date(record.created_at).toLocaleTimeString()}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
