// Thin client for the console's REST API. Every state-changing request
// carries X-KFS-Request, which the server requires (cross-site forms
// cannot set custom headers).

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function call(method, url, body) {
  const init = { method, credentials: 'same-origin', headers: {} };
  if (method !== 'GET') init.headers['X-KFS-Request'] = '1';
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await fetch(url, init);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, data.detail ?? data.error ?? `Request failed (${res.status}).`);
  return data;
}

const q = (path) => encodeURIComponent(path);

export const api = {
  session: () => call('GET', '/api/session'),
  login: (password) => call('POST', '/api/login', { password }),
  logout: () => call('POST', '/api/logout'),

  list: (path) => call('GET', `/api/files/list?path=${q(path)}`),
  blocks: (path) => call('GET', `/api/files/blocks?path=${q(path)}`),
  mkdir: (path) => call('POST', '/api/files/mkdir', { path }),
  rename: (source, target) => call('POST', '/api/files/rename', { source, target }),
  remove: (path, recursive = false) =>
    call('DELETE', `/api/files?path=${q(path)}${recursive ? '&recursive=true' : ''}`),
  downloadUrl: (path) => `/api/files/download?path=${q(path)}`,

  // XHR rather than fetch: it reports upload progress.
  upload(path, file, onProgress, overwrite = false) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('PUT', `/api/files/content?path=${q(path)}${overwrite ? '&overwrite=true' : ''}`);
      xhr.setRequestHeader('X-KFS-Request', '1');
      xhr.upload.onprogress = (e) => e.lengthComputable && onProgress?.(e.loaded / e.total);
      xhr.onload = () => {
        let data = {};
        try { data = JSON.parse(xhr.responseText); } catch { /* not JSON */ }
        if (xhr.status >= 200 && xhr.status < 300) resolve(data);
        else reject(new ApiError(xhr.status, data.detail ?? data.error ?? `Upload failed (${xhr.status}).`));
      };
      xhr.onerror = () => reject(new ApiError(0, 'The connection to the console was lost.'));
      xhr.send(file);
    });
  },

  cluster: () => call('GET', '/api/cluster'),
  stopNode: (id, how) => call('POST', `/api/cluster/nodes/${id}/stop`, { how }),
  startNode: (id) => call('POST', `/api/cluster/nodes/${id}/start`),
  nodeLog: (id) => call('GET', `/api/cluster/nodes/${id}/log?lines=60`),
  lock: () => call('POST', '/api/volume/lock'),
  unlock: (passphrase) => call('POST', '/api/volume/unlock', { passphrase }),

  attack: (kind, body = {}) => call('POST', `/api/attacks/${kind}`, body),
};
