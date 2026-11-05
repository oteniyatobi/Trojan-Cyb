const paths = {
  chevron: 'M6 9l6 6 6-6',
  hosts: 'M3 4h18v12H3z M8 21h8 M12 16v5',
  check: 'M5 12l4 4L19 6',
  warning: 'M12 3 2 21h20z M12 9v5 M12 17h.01',
  menu: 'M3 6h18 M3 12h18 M3 18h18',
  logout: 'M9 3H3v18h6 M9 12h12 M16 7l5 5-5 5',
  sun: 'M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0 M12 2v2 M12 20v2 M2 12h2 M20 12h2 M5 5l1.5 1.5 M17.5 17.5 19 19 M5 19l1.5-1.5 M17.5 6.5 19 5',
  moon: 'M21 13a9 9 0 1 1-10-10 7 7 0 0 0 10 10z',
  overview: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  alerts: 'M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9 M10 21h4',
  findings: 'M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7z M12 8v5 M12 16h.01',
  scans: 'M8 3H3v5 M16 3h5v5 M3 16v5h5 M21 16v5h-5 M7 12h10 M12 7v10',
  health: 'M3 12h4l3-8 4 16 3-8h4',
  settings:
    'M4 6h7 M15 6h5 M4 12h2 M10 12h10 M4 18h10 M18 18h2 M11 3v6 M6 9v6 M14 15v6',
  search: 'M16 10a6 6 0 1 1-12 0 6 6 0 0 1 12 0 M14.5 14.5 21 21',
  arrow: 'M5 12h14 M13 6l6 6-6 6',
  back: 'M19 12H5 M11 6l-6 6 6 6',
}

function Icon({ name }) {
  return (
    <svg
      className="icon"
      width="20"
      height="20"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={paths[name]} />
    </svg>
  )
}

export default Icon
