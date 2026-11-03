// File manager over the encrypted volume, plus "What the servers store":
// the selected file next to the encrypted blocks the servers actually hold.

import { useCallback, useEffect, useRef, useState } from 'react';

import { useI18n } from '../i18n/index.jsx';
import { api } from '../lib/api.js';
import { bytes, hexGroups, joinPath, when } from '../lib/format.js';
import { Explain, useAdvanced } from './Learn.jsx';

function Breadcrumbs({ path, onGo }) {
  const { t } = useI18n();
  const parts = path.split('/').filter(Boolean);
  return (
    <nav aria-label="Folder" className="flex min-w-0 flex-wrap items-center gap-1 text-sm">
      <button type="button" className="rounded px-1.5 py-0.5 text-cyan hover:bg-deck" onClick={() => onGo('/')}>
        {t('files.root')}
      </button>
      {parts.map((p, i) => (
        <span key={i} className="flex items-center gap-1">
          <span className="text-mist">/</span>
          <button type="button" className="truncate rounded px-1.5 py-0.5 text-cyan hover:bg-deck"
                  onClick={() => onGo(`/${parts.slice(0, i + 1).join('/')}`)}>{p}</button>
        </span>
      ))}
    </nav>
  );
}

function InlineForm({ label, initial = '', submit, onSubmit, onCancel }) {
  const { t } = useI18n();
  const [value, setValue] = useState(initial);
  return (
    <form className="flex flex-wrap items-center gap-2" onSubmit={(e) => { e.preventDefault(); if (value.trim()) onSubmit(value.trim()); }}>
      <label className="sr-only" htmlFor="inline-name">{label}</label>
      <input id="inline-name" className="field max-w-xs" autoFocus value={value} placeholder={label}
             onChange={(e) => setValue(e.target.value)} />
      <button type="submit" className="btn btn-primary">{submit}</button>
      <button type="button" className="btn" onClick={onCancel}>{t('files.cancel')}</button>
    </form>
  );
}

export function StoredBlocks({ path }) {
  const { t } = useI18n();
  const advanced = useAdvanced();
  const [view, setView] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let live = true;
    setView(null);
    setError('');
    if (!path) return undefined;
    const load = () => api.blocks(path).then((v) => live && setView(v)).catch((e) => live && setError(e.message));
    load();
    const timer = setInterval(load, 4000); // blocks reach the servers on writeback
    return () => { live = false; clearInterval(timer); };
  }, [path]);

  if (!path) return <p className="text-mist">{t('stored.pick')}</p>;
  if (error) return <p className="text-coral">{error}</p>;
  if (!view) return <p className="text-mist">…</p>;
  const name = view.path.split('/').pop();

  return (
    <div className="space-y-4">
      <p className="max-w-prose">
        {view.blockCount === 0 ? t('stored.empty')
          : t('stored.intro', { name, n: view.blockCount.toLocaleString(), bs: bytes(view.blockSize) })}
      </p>
      {view.blockCount > 0 && (
        <div className="grid gap-4 md:grid-cols-2">
          <div className="min-w-0 rounded-lg border border-rule p-3">
            <h4 className="mb-2 font-display font-bold text-neon">{t('stored.youSee')}</h4>
            <pre className="whitespace-pre-wrap break-words font-mono text-[13px] text-bone">{view.plainText}</pre>
          </div>
          <div className="min-w-0 rounded-lg border border-rule p-3">
            <h4 className="mb-2 font-display font-bold text-cyan">{t('stored.serversSee')}</h4>
            {view.blocks[0]?.copies[0] ? (
              <pre className="whitespace-pre-wrap break-all font-mono text-[13px] text-mist">
                {hexGroups(view.blocks[0].copies[0].cipherHex)}
              </pre>
            ) : <p className="text-sm text-mist">{t('stored.noCopies')}</p>}
          </div>
        </div>
      )}
      <ol className="space-y-2">
        {view.blocks.map((b) => (
          <li key={b.index} className="rounded-lg border border-rule p-3">
            <div className="mb-1.5 font-display text-sm font-bold">{t('stored.block', { i: b.index })}</div>
            {b.copies.length === 0 ? <p className="text-sm text-mist">{t('stored.noCopies')}</p> : (
              <ul className="flex flex-wrap gap-2">
                {b.copies.map((c) => (
                  <li key={`${c.node}-${c.parity}`} className="chip border-cyan-dim text-bone">
                    <span className="text-cyan">{t('stored.copyOn', { node: c.node })}</span>
                    <span className="text-mist">{t('stored.generation', { g: c.generation })}</span>
                    {advanced && <span className="font-mono font-normal text-mist">{t('stored.object', { id: c.objectId })}</span>}
                  </li>
                ))}
              </ul>
            )}
          </li>
        ))}
      </ol>
      {view.shown < view.blockCount && (
        <p className="text-sm text-mist">{t('stored.more', { shown: view.shown, n: view.blockCount.toLocaleString() })}</p>
      )}
    </div>
  );
}

// target: {dir, file?} to open (from the overview's tree), or null.
export default function FilesView({ target, mounted, notify }) {
  const { t } = useI18n();
  const [dir, setDir] = useState(target?.dir ?? '/');
  const [listing, setListing] = useState(null);
  const [selected, setSelected] = useState(target?.file ?? null);
  const [form, setForm] = useState(null); // {kind: 'mkdir'} | {kind: 'rename', entry}
  const [dragging, setDragging] = useState(false);
  const [uploads, setUploads] = useState([]); // [{name, progress}]
  const input = useRef(null);

  const load = useCallback(async (path = dir) => {
    try {
      const l = await api.list(path);
      setListing(l);
    } catch (e) {
      setListing({ path, entries: [], error: e.message });
    }
  }, [dir]);

  useEffect(() => { load(dir); }, [dir, load, mounted]);
  useEffect(() => {
    if (target) {
      setDir(target.dir);
      setSelected(target.file ?? null);
    }
  }, [target]);

  const uploadFiles = async (files) => {
    for (const file of files) {
      const target = joinPath(dir, file.name);
      setUploads((u) => [...u, { name: file.name, progress: 0 }]);
      const send = (overwrite) => api.upload(target, file, (p) =>
        setUploads((u) => u.map((x) => (x.name === file.name ? { ...x, progress: p } : x))), overwrite);
      try {
        try {
          await send(false);
        } catch (e) {
          if (e.status !== 409 || !window.confirm(t('files.confirmReplace', { name: file.name }))) throw e;
          await send(true);
        }
        notify('ok', t('files.uploaded', { name: file.name }));
        setSelected(target);
      } catch (e) {
        if (e.status === 409) continue; // the user chose to keep the existing file
        notify('bad', e.status === 403 ? t('files.blocked', { name: file.name }) : e.message);
      } finally {
        setUploads((u) => u.filter((x) => x.name !== file.name));
      }
    }
    load();
  };

  const act = async (fn, okMsg) => {
    try {
      await fn();
      if (okMsg) notify('ok', okMsg);
      setForm(null);
      load();
    } catch (e) {
      notify('bad', e.message);
    }
  };

  if (!mounted) return <p className="text-mist">{t('files.locked')}</p>;

  return (
    <div className="grid gap-8 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
      <Explain id="files.list">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <Breadcrumbs path={listing?.path ?? dir} onGo={(p) => { setDir(p); setSelected(null); }} />
          <div className="flex gap-2">
            <button type="button" className="btn" onClick={() => setForm({ kind: 'mkdir' })}>{t('files.newFolder')}</button>
            <button type="button" className="btn btn-primary" onClick={() => input.current?.click()}>{t('files.upload')}</button>
            <input ref={input} type="file" multiple className="hidden"
                   onChange={(e) => { uploadFiles([...e.target.files]); e.target.value = ''; }} />
          </div>
        </div>

        {form?.kind === 'mkdir' && (
          <div className="mt-3">
            <InlineForm label={t('files.folderName')} submit={t('files.create')} onCancel={() => setForm(null)}
                        onSubmit={(name) => act(() => api.mkdir(joinPath(dir, name)))} />
          </div>
        )}
        {form?.kind === 'rename' && (
          <div className="mt-3">
            <InlineForm label={t('files.newName')} initial={form.entry.name} submit={t('files.save')}
                        onCancel={() => setForm(null)}
                        onSubmit={(name) => act(() => api.rename(joinPath(dir, form.entry.name), joinPath(dir, name)))} />
          </div>
        )}

        <div onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
             onDragLeave={() => setDragging(false)}
             onDrop={(e) => { e.preventDefault(); setDragging(false); uploadFiles([...e.dataTransfer.files]); }}
             className={`mt-4 min-h-[16rem] rounded-lg border ${dragging ? 'border-dashed border-cyan bg-cyan-deep/40' : 'border-rule'}`}>
          {uploads.map((u) => (
            <div key={u.name} className="border-b border-rule px-4 py-2 text-sm">
              {t('files.uploading', { name: u.name })}
              <div className="mt-1 h-1 rounded bg-rule"><div className="h-1 rounded bg-cyan" style={{ width: `${Math.round(u.progress * 100)}%` }} /></div>
            </div>
          ))}
          {listing?.error && <p className="p-4 text-coral">{listing.error}</p>}
          {listing && !listing.error && listing.entries.length === 0 && !uploads.length && (
            <p className="p-8 text-center text-mist">{dragging ? t('files.drop') : t('files.empty')}</p>
          )}
          {listing?.entries?.length > 0 && (
            <table className="w-full table-fixed text-sm">
              <thead>
                <tr className="border-b border-rule text-left text-xs text-mist">
                  <th className="px-4 py-2 font-normal">{t('files.name')}</th>
                  <th className="w-24 px-2 py-2 text-right font-normal">{t('files.size')}</th>
                  <th className="hidden w-36 px-2 py-2 font-normal sm:table-cell">{t('files.modified')}</th>
                  <th className="w-52 px-2 py-2"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {listing.entries.map((e) => {
                  const path = joinPath(listing.path, e.name);
                  const isSel = selected === path;
                  return (
                    <tr key={e.name} className={`border-b border-rule/60 ${isSel ? 'bg-cyan-deep/50' : 'hover:bg-deck'}`}>
                      <td className="truncate px-4 py-2">
                        <button type="button" className={`truncate text-left ${e.dir ? 'font-bold text-cyan' : 'text-bone'}`}
                                onClick={() => (e.dir ? (setDir(path), setSelected(null)) : setSelected(path))}>
                          {e.name}{e.dir ? '/' : ''}
                        </button>
                      </td>
                      <td className="num px-2 py-2 text-right text-mist">{e.dir ? '' : bytes(e.size)}</td>
                      <td className="num hidden px-2 py-2 text-mist sm:table-cell">{when(e.mtime * 1000)}</td>
                      <td className="px-2 py-1">
                        <div className="flex justify-end gap-1">
                          {!e.dir && <a className="rounded px-1.5 py-1 text-xs text-cyan hover:bg-deck" href={api.downloadUrl(path)}>{t('files.download')}</a>}
                          <button type="button" className="rounded px-1.5 py-1 text-xs text-mist hover:bg-deck hover:text-bone"
                                  onClick={() => setForm({ kind: 'rename', entry: e })}>{t('files.rename')}</button>
                          <button type="button" className="rounded px-1.5 py-1 text-xs text-coral hover:bg-deck"
                                  onClick={() => {
                                    if (window.confirm(t(e.dir ? 'files.confirmDeleteFolder' : 'files.confirmDelete', { name: e.name }))) {
                                      act(() => api.remove(path, e.dir));
                                      if (isSel) setSelected(null);
                                    }
                                  }}>{t('files.delete')}</button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </Explain>

      <Explain id="files.stored">
        <h3 className="panel-title mb-3">{t('stored.title')}</h3>
        <StoredBlocks path={selected} />
      </Explain>
    </div>
  );
}
