function Badge({ children }) {
  const tone = children.toLowerCase().replaceAll(' ', '-')
  return <span className={`badge badge-${tone}`}>{children}</span>
}

export default Badge
