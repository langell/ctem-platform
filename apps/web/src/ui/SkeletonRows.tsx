export function SkeletonRows({ columns, rows = 6 }: { columns: number; rows?: number }) {
  return Array.from({ length: rows }, (_, row) => (
    <tr key={row}>
      {Array.from({ length: columns }, (_, col) => (
        <td key={col}>
          <span className="skeleton" />
        </td>
      ))}
    </tr>
  ));
}
