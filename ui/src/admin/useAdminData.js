import { useEffect, useState } from 'react'

export default function useAdminData(getToken, fetcher, reloadKey = 0) {
  const [state, setState] = useState({ data: null, error: '', key: -1 })

  useEffect(() => {
    let active = true
    getToken()
      .then((token) => fetcher(token))
      .then((data) => {
        if (active) setState({ data, error: '', key: reloadKey })
      })
      .catch((error) => {
        if (active) setState((current) => ({ ...current, error: error.message, key: reloadKey }))
      })
    return () => {
      active = false
    }
  }, [getToken, fetcher, reloadKey])

  return { data: state.data, error: state.error, loading: state.key !== reloadKey }
}
