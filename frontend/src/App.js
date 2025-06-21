import React, { useState } from 'react';

const App = () => {
  // State definitions
  const [symInputData, setSymInputData] = useState('');
  const [symSecretKey, setSymSecretKey] = useState('');
  const [symAlgorithm, setSymAlgorithm] = useState('AES');
  const [symOutputData, setSymOutputData] = useState('');

  const [hashInputData, setHashInputData] = useState('');
  const [hashAlgorithm, setHashAlgorithm] = useState('SHA256');
  const [hashOutputData, setHashOutputData] = useState('');

  const [encodeInputData, setEncodeInputData] = useState('');
  const [encodeMethod, setEncodeMethod] = useState('Base64');
  const [encodeOutputData, setEncodeOutputData] = useState('');

  const [message, setMessage] = useState({ text: '', type: '' });

  // Generic API request handler
  const handleRequest = async ({ url, payload, onSuccess, onError, successMessage }) => {
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Server error');

      onSuccess(data);
      showMessage(successMessage, 'success');
    } catch (err) {
      console.error(err);
      onError();
      showMessage(err.message, 'error');
    }
  };

  // UI message handler
  const showMessage = (text, type = 'info') => {
    setMessage({ text, type });
    setTimeout(() => setMessage({ text: '', type: '' }), 5000);
  };

  // Operations
  const encryptSymData = () => {
    if (!symInputData || !symSecretKey) return showMessage("Enter both text and secret key.", 'error');
    handleRequest({
      url: 'http://localhost:3000/api/symmetric/encrypt',
      payload: { text: symInputData, key: symSecretKey, algorithm: symAlgorithm },
      onSuccess: data => setSymOutputData(data.ciphertext),
      onError: () => setSymOutputData(''),
      successMessage: `Encrypted using ${symAlgorithm}.`,
    });
  };

  const decryptSymData = () => {
    if (!symInputData || !symSecretKey) return showMessage("Enter both ciphertext and secret key.", 'error');
    handleRequest({
      url: 'http://localhost:3000/api/symmetric/decrypt',
      payload: { text: symInputData, key: symSecretKey, algorithm: symAlgorithm },
      onSuccess: data => setSymOutputData(data.plaintext),
      onError: () => setSymOutputData(''),
      successMessage: `Decrypted using ${symAlgorithm}.`,
    });
  };

  const hashData = () => {
    if (!hashInputData) return showMessage("Enter data to hash.", 'error');
    handleRequest({
      url: 'http://localhost:3000/api/hash',
      payload: { text: hashInputData, algorithm: hashAlgorithm },
      onSuccess: data => setHashOutputData(data.hash),
      onError: () => setHashOutputData(''),
      successMessage: `Hashed using ${hashAlgorithm}.`,
    });
  };

  const encodeData = () => {
    if (!encodeInputData) return showMessage("Enter data to encode.", 'error');
    handleRequest({
      url: 'http://localhost:3000/api/encode',
      payload: { text: encodeInputData, method: encodeMethod },
      onSuccess: data => setEncodeOutputData(data.encoded),
      onError: () => setEncodeOutputData(''),
      successMessage: `Encoded using ${encodeMethod}.`,
    });
  };

  const decodeData = () => {
    if (!encodeInputData) return showMessage("Enter data to decode.", 'error');
    handleRequest({
      url: 'http://localhost:3000/api/decode',
      payload: { text: encodeInputData, method: encodeMethod },
      onSuccess: data => setEncodeOutputData(data.decoded),
      onError: () => setEncodeOutputData(''),
      successMessage: `Decoded using ${encodeMethod}.`,
    });
  };

  return (
    <div className="min-h-screen p-4 bg-gray-900 text-white font-sans">
      <div className="max-w-3xl mx-auto bg-gray-800 p-6 rounded-xl shadow-xl">
        <h1 className="text-3xl font-bold mb-4 text-center">Crypto Tool</h1>

        {message.text && (
          <div className={`mb-4 p-3 rounded ${message.type === 'error' ? 'bg-red-600' : 'bg-green-600'}`}>{message.text}</div>
        )}

        {/* Section for Symmetric Encryption */}
        <section className="mb-8">
          <h2 className="text-xl font-semibold mb-2">Symmetric Encryption</h2>
          <textarea className="w-full mb-2 p-2 bg-gray-700" value={symInputData} onChange={e => setSymInputData(e.target.value)} placeholder="Text to encrypt/decrypt" />
          <input className="w-full mb-2 p-2 bg-gray-700" value={symSecretKey} onChange={e => setSymSecretKey(e.target.value)} placeholder="Secret Key" />
          <select className="w-full mb-2 p-2 bg-gray-700" value={symAlgorithm} onChange={e => setSymAlgorithm(e.target.value)}>
            {['AES', 'DES', 'TripleDES', 'Blowfish', 'Twofish', 'RC4', 'RC5', 'RC6', 'ChaCha20'].map(algo => (
              <option key={algo} value={algo}>{algo}</option>
            ))}
          </select>
          <div className="flex gap-2 mb-2">
            <button className="flex-1 bg-blue-600 p-2 rounded" onClick={encryptSymData}>Encrypt</button>
            <button className="flex-1 bg-yellow-600 p-2 rounded" onClick={decryptSymData}>Decrypt</button>
          </div>
          <textarea className="w-full p-2 bg-gray-700" readOnly value={symOutputData} placeholder="Output" />
        </section>

        {/* Hashing */}
        <section className="mb-8">
          <h2 className="text-xl font-semibold mb-2">Hashing</h2>
          <textarea className="w-full mb-2 p-2 bg-gray-700" value={hashInputData} onChange={e => setHashInputData(e.target.value)} placeholder="Text to hash" />
          <select className="w-full mb-2 p-2 bg-gray-700" value={hashAlgorithm} onChange={e => setHashAlgorithm(e.target.value)}>
            {['MD5', 'SHA1', 'SHA256', 'SHA512', 'RIPEMD160', 'SHA3', 'BLAKE2', 'bcrypt', 'scrypt', 'PBKDF2'].map(algo => (
              <option key={algo} value={algo}>{algo}</option>
            ))}
          </select>
          <button className="w-full bg-green-600 p-2 rounded" onClick={hashData}>Hash</button>
          <textarea className="w-full mt-2 p-2 bg-gray-700" readOnly value={hashOutputData} placeholder="Hashed Output" />
        </section>

        {/* Encoding */}
        <section>
          <h2 className="text-xl font-semibold mb-2">Encoding</h2>
          <textarea className="w-full mb-2 p-2 bg-gray-700" value={encodeInputData} onChange={e => setEncodeInputData(e.target.value)} placeholder="Text to encode/decode" />
          <select className="w-full mb-2 p-2 bg-gray-700" value={encodeMethod} onChange={e => setEncodeMethod(e.target.value)}>
            {['Base64', 'Hex', 'Base32', 'Base58', 'ROT13', 'URL Encoding'].map(method => (
              <option key={method} value={method}>{method}</option>
            ))}
          </select>
          <div className="flex gap-2 mb-2">
            <button className="flex-1 bg-indigo-600 p-2 rounded" onClick={encodeData}>Encode</button>
            <button className="flex-1 bg-pink-600 p-2 rounded" onClick={decodeData}>Decode</button>
          </div>
          <textarea className="w-full p-2 bg-gray-700" readOnly value={encodeOutputData} placeholder="Encoded/Decoded Output" />
        </section>
      </div>
    </div>
  );
};

export default App;
