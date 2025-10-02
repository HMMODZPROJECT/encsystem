/*
  Struktur file terenkripsi:
  [0..15]   salt (16 bytes)
  [16..27]  iv   (12 bytes)
  [28..29]  fnameLen (Uint16 big-endian)
  [30..(30+fnameLen-1)] filename UTF-8 bytes
  [rest]    ciphertext (ArrayBuffer)
*/

const encFileInput = document.getElementById('enc-file');
const encPassInput = document.getElementById('enc-pass');
const encItersInput = document.getElementById('enc-iters');
const encBtn = document.getElementById('btn-encrypt');
const encLog = document.getElementById('enc-log');
const encBar = document.getElementById('enc-bar');

const decFileInput = document.getElementById('dec-file');
const decPassInput = document.getElementById('dec-pass');
const decItersInput = document.getElementById('dec-iters');
const decBtn = document.getElementById('btn-decrypt');
const decLog = document.getElementById('dec-log');
const decBar = document.getElementById('dec-bar');

function log(el, msg){
  el.textContent += msg + '\n';
  el.scrollTop = el.scrollHeight;
}

function updateProgress(bar, pct){
  bar.style.width = Math.max(0, Math.min(100, pct)) + '%';
}

/* Utility: concat ArrayBuffers */
function concatBuffers(buffers){
  const total = buffers.reduce((s,b)=>s + b.byteLength, 0);
  const tmp = new Uint8Array(total);
  let offset = 0;
  for(const b of buffers){
    tmp.set(new Uint8Array(b), offset);
    offset += b.byteLength;
  }
  return tmp.buffer;
}

/* Derive AES-GCM key from password and salt using PBKDF2 */
async function deriveKey(password, salt, iterations){
  const enc = new TextEncoder();
  const passKey = await crypto.subtle.importKey('raw', enc.encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  const derived = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: iterations, hash: 'SHA-256' },
    passKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt','decrypt']
  );
  return derived;
}

/* Read file as ArrayBuffer with simple progress reporting */
function readFileAsArrayBuffer(file, onProgress){
  return new Promise((resolve,reject)=>{
    const reader = new FileReader();
    reader.onerror = ()=> reject(reader.error);
    reader.onprogress = (ev)=> {
      if(ev.lengthComputable && onProgress) onProgress(ev.loaded / ev.total);
    };
    reader.onload = ()=> resolve(reader.result);
    reader.readAsArrayBuffer(file);
  });
}

encBtn.addEventListener('click', async ()=>{
  encLog.textContent = '';
  updateProgress(encBar, 0);
  const file = encFileInput.files[0];
  const password = encPassInput.value || '';
  const iterations = parseInt(encItersInput.value) || 100000;

  if(!file){ log(encLog, 'Pilih file terlebih dahulu.'); return; }
  if(!password){ log(encLog, 'Masukkan password.'); return; }
  try{
    log(encLog, `Membaca file: ${file.name} (${file.size} bytes)...`);
    const data = await readFileAsArrayBuffer(file, pct=> updateProgress(encBar, pct*30));
    updateProgress(encBar, 35);

    log(encLog, 'Menghasilkan salt & iv acak...');
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    log(encLog, `Menurunkan kunci via PBKDF2 (${iterations} iterasi)...`);
    const key = await deriveKey(password, salt.buffer, iterations);
    updateProgress(encBar, 55);

    log(encLog, 'Mengenkripsi data dengan AES-GCM...');
    const cipher = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, data);
    updateProgress(encBar, 85);

    const enc = new TextEncoder();
    const fnameBytes = enc.encode(file.name);
    const fnameLen = fnameBytes.length;
    if(fnameLen > 65535) throw new Error('Nama file terlalu panjang.');

    const fnameLenBuf = new Uint8Array(2);
    fnameLenBuf[0] = (fnameLen >> 8) & 0xFF;
    fnameLenBuf[1] = fnameLen & 0xFF;

    const outBuf = concatBuffers([salt.buffer, iv.buffer, fnameLenBuf.buffer, fnameBytes.buffer, cipher]);
    updateProgress(encBar, 100);

    const blob = new Blob([outBuf], { type: 'application/octet-stream' });
    const outName = file.name + '.enc';
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = outName;
    document.body.appendChild(a); a.click();
    a.remove();
    URL.revokeObjectURL(url);

    log(encLog, `Selesai: file terenkripsi di-download sebagai '${outName}'.`);
  }catch(err){
    console.error(err);
    log(encLog, 'Error: ' + err.message);
    updateProgress(encBar, 0);
  }
});

decBtn.addEventListener('click', async ()=>{
  decLog.textContent = '';
  updateProgress(decBar, 0);
  const file = decFileInput.files[0];
  const password = decPassInput.value || '';
  const iterations = parseInt(decItersInput.value) || 100000;

  if(!file){ log(decLog, 'Pilih file terenkripsi terlebih dahulu.'); return; }
  if(!password){ log(decLog, 'Masukkan password.'); return; }

  try{
    log(decLog, `Membaca file terenkripsi: ${file.name} (${file.size} bytes)...`);
    const data = await readFileAsArrayBuffer(file, pct=> updateProgress(decBar, pct*30));
    updateProgress(decBar, 35);

    const u8 = new Uint8Array(data);
    if(u8.byteLength < 30) throw new Error('File terlalu pendek atau bukan file yang valid.');

    const salt = u8.slice(0,16).buffer;
    const iv = u8.slice(16,28).buffer;
    const fnameLen = (u8[28] << 8) | u8[29];
    if(30 + fnameLen > u8.length) throw new Error('Metadata nama file rusak.');

    const fnameBytes = u8.slice(30, 30 + fnameLen);
    const decoder = new TextDecoder();
    const origName = decoder.decode(fnameBytes);

    const cipherStart = 30 + fnameLen;
    const cipherBuf = u8.slice(cipherStart).buffer;

    log(decLog, `Nama asli file: ${origName}`);
    log(decLog, `Menurunkan kunci via PBKDF2 (${iterations} iterasi)...`);
    const key = await deriveKey(password, salt, iterations);
    updateProgress(decBar, 60);

    log(decLog, 'Mendekripsi...');
    let plain;
    try{
      plain = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, cipherBuf);
    }catch(e){
      throw new Error('Gagal dekripsi — mungkin password salah atau file korup.');
    }
    updateProgress(decBar, 95);

    const blob = new Blob([plain], { type: 'application/octet-stream' });
    let outName = origName;
    if(outName.endsWith('.enc')) outName = outName.slice(0, -4);
    if(!outName) outName = 'decrypted.bin';

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = outName;
    document.body.appendChild(a); a.click();
    a.remove();
    URL.revokeObjectURL(url);

    log(decLog, `Selesai: file terdekripsi di-download sebagai '${outName}'.`);
    updateProgress(decBar, 100);
  }catch(err){
    console.error(err);
    log(decLog, 'Error: ' + err.message);
    updateProgress(decBar, 0);
  }
});
