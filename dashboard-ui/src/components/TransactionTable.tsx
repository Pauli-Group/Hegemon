import type { TransferRecord } from '../types/node';
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
            <td>
              <span className={`${styles.badge} ${record.direction === 'incoming' ? styles.incoming : styles.outgoing}`}>
                {record.direction}
              </span>
            </td>
            <td className={styles.address}>{record.address}</td>
            <td>{record.amount.toFixed(2)}</td>
            <td>{record.status}</td>
            <td>{record.confirmations}</td>
            <td>{new Date(record.created_at).toLocaleTimeString()}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
