import { useState } from 'react'
import Badge from '../components/Badge.jsx'

function Health({ services, hosts, snapshotDate }) {
  const [search, setSearch] = useState('')
  const filtered = hosts.filter((host) =>
    `${host.name} ${host.ip}`.toLowerCase().includes(search.toLowerCase()),
  )

  return (
    <>
      <div className="kpi-grid service-grid">
        {services.map((service) => (
          <section className="kpi-card service-card" key={service.name}>
            <h2>{service.name}</h2>
            <Badge>{service.status}</Badge>
            <p>{service.description}</p>
            <span className="cell-note">{service.detail}</span>
          </section>
        ))}
      </div>
      <section className="panel">
        <div className="section-heading">
          <h2>Monitored hosts</h2>
          <span className="panel-caption">
            {hosts.filter((host) => host.status === 'Online').length} of{' '}
            {hosts.length} online · Demo snapshot
          </span>
        </div>
        <label className="host-search">
          Search hosts
          <input
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Host name or IP address"
          />
        </label>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Host</th>
                <th>IP address</th>
                <th>Operating system</th>
                <th>Status</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((host) => (
                <tr key={host.id}>
                  <td>
                    <strong>{host.name}</strong>
                    <span className="cell-note">{host.id}</span>
                  </td>
                  <td>{host.ip}</td>
                  <td>{host.system}</td>
                  <td>
                    <Badge>{host.status}</Badge>
                  </td>
                  <td>
                    {host.lastSeen}
                    <span className="cell-note">{snapshotDate}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {filtered.length === 0 && (
          <p className="empty-state">No hosts match your search.</p>
        )}
      </section>
    </>
  )
}

export default Health
