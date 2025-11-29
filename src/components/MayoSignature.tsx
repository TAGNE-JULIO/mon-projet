'use client';

import React, { useState } from 'react';
import { Key, FileText, Shield, CheckCircle, XCircle, AlertCircle, Copy, Info } from 'lucide-react';
import { MAYO_PARAMS } from '../lib/mayo/params';
import { compactKeyGen, sign, verify } from '../lib/mayo/algorithms';
import type { PublicKey, SecretKey, ExpandedSK, Signature } from '../lib/mayo/algorithms';

export default function MayoSignature() {
    const [activeTab, setActiveTab] = useState('generate');
    const [selectedVariant, setSelectedVariant] = useState('MAYO_2');
    const [publicKey, setPublicKey] = useState<PublicKey | null>(null);
    const [secretKey, setSecretKey] = useState<SecretKey | null>(null);
    const [expandedSK, setExpandedSK] = useState<ExpandedSK | null>(null);
    const [document, setDocument] = useState('');
    const [signature, setSignature] = useState<Signature | null>(null);
    const [verifyDoc, setVerifyDoc] = useState('');
    const [verifySignature, setVerifySignature] = useState('');
    const [verificationResult, setVerificationResult] = useState<any>(null);
    const [isProcessing, setIsProcessing] = useState(false);
    const [logs, setLogs] = useState<Array<{ timestamp: string; msg: string }>>([]);

    const params = MAYO_PARAMS[selectedVariant];

    const addLog = (msg: string) => {
        const timestamp = new Date().toLocaleTimeString();
        setLogs(prev => [...prev, { timestamp, msg }]);
    };

    const handleGenerateKeys = async () => {
        setIsProcessing(true);
        setLogs([]);

        const result = await compactKeyGen(params, selectedVariant, addLog);
        setPublicKey(result.publicKey);
        setSecretKey(result.secretKey);
        setExpandedSK(result.expandedSK);

        setIsProcessing(false);
    };

    const handleSign = async () => {
        if (!document || !expandedSK) return;

        setIsProcessing(true);
        setLogs([]);

        const sig = await sign(document, expandedSK, params, selectedVariant, addLog);
        setSignature(sig);

        setIsProcessing(false);
    };

    const handleVerify = async () => {
        if (!verifyDoc || !verifySignature) return;

        setIsProcessing(true);
        setLogs([]);

        try {
            const sig: Signature = JSON.parse(verifySignature);
            const verifyParams = MAYO_PARAMS[sig.variant];
            const isValid = await verify(verifyDoc, sig, verifyParams, addLog);

            setVerificationResult({
                valid: isValid,
                variant: sig.variant,
                signedAt: new Date(sig.timestamp).toLocaleString()
            });
        } catch (e) {
            addLog('❌ Erreur: ' + (e as Error).message);
            setVerificationResult({ valid: false, error: (e as Error).message });
        }

        setIsProcessing(false);
    };

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
        addLog('📋 Copié');
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-4">
            <div className="max-w-7xl mx-auto">

                {/* Header */}
                <div className="text-center mb-6">
                    <div className="flex items-center justify-center mb-4">
                        <Shield className="w-12 h-12 text-cyan-400 animate-pulse" />
                    </div>
                    <h1 className="text-4xl font-bold text-white mb-2">
                        MAYO Digital Signature
                    </h1>
                    <p className="text-blue-200 text-sm mb-4">
                        Post-Quantum Cryptography - Multivariate Quadratic Signatures
                    </p>

                    {/* Variant Selector */}
                    <div className="flex justify-center gap-2 mb-4">
                        {Object.keys(MAYO_PARAMS).map((variant) => (
                            <button
                                key={variant}
                                onClick={() => setSelectedVariant(variant)}
                                className={`px-4 py-2 rounded-lg text-sm font-semibold transition-all $${
                                    selectedVariant === variant
                                        ? 'bg-cyan-500 text-white shadow-lg'
                                        : 'bg-white/10 text-blue-200 hover:bg-white/20'
                                }`}
                            >
                                {variant}
                            </button>
                        ))}
                    </div>

                    <div className="inline-block bg-blue-800/40 backdrop-blur-sm px-6 py-2 rounded-full">
                        <p className="text-cyan-300 text-xs">
                            <strong>SK:</strong> {params.sk_size}B |
                            <strong> PK:</strong> {params.pk_size}B |
                            <strong> Sig:</strong> {params.sig_size}B
                        </p>
                    </div>
                </div>

                {/* Tabs */}
                <div className="flex gap-2 mb-4 bg-black/30 backdrop-blur-md p-2 rounded-2xl">
                    {[
                        { id: 'generate', label: 'Générer', icon: Key },
                        { id: 'sign', label: 'Signer', icon: FileText },
                        { id: 'verify', label: 'Vérifier', icon: Shield }
                    ].map(({ id, label, icon: Icon }) => (
                        <button
                            key={id}
                            onClick={() => setActiveTab(id)}
                            className={`flex-1 py-3 px-4 rounded-xl font-semibold transition-all flex items-center justify-center gap-2 ${
                                activeTab === id
                                    ? 'bg-gradient-to-r from-cyan-500 to-blue-500 text-white shadow-lg'
                                    : 'text-blue-200 hover:bg-white/10'
                            }`}
                        >
                            <Icon className="w-4 h-4" />
                            {label}
                        </button>
                    ))}
                </div>

                <div className="grid lg:grid-cols-3 gap-4">

                    {/* Main Column */}
                    <div className="lg:col-span-2 bg-white/10 backdrop-blur-lg rounded-2xl p-6 border border-white/20">

                        {/* Generate Tab */}
                        {activeTab === 'generate' && (
                            <div className="space-y-4">
                                <h2 className="text-2xl font-bold text-white">Algorithm 4: KeyGen</h2>

                                <button
                                    onClick={handleGenerateKeys}
                                    disabled={isProcessing}
                                    className="w-full bg-gradient-to-r from-green-500 to-emerald-600 text-white py-3 rounded-xl font-semibold flex items-center justify-center gap-2"
                                >
                                    <Key className="w-5 h-5" />
                                    {isProcessing ? 'Génération...' : 'Générer Clés'}
                                </button>

                                {publicKey && secretKey && (
                                    <div className="space-y-3">
                                        <div className="bg-green-500/20 p-4 rounded-xl border border-green-400/30">
                                            <div className="flex justify-between items-center mb-2">
                                                <h3 className="text-green-300 font-semibold text-sm">Clé Publique</h3>
                                                <button onClick={() => copyToClipboard(JSON.stringify(publicKey))}>
                                                    <Copy className="w-4 h-4 text-green-300" />
                                                </button>
                                            </div>
                                            <div className="bg-black/40 p-2 rounded text-xs font-mono break-all text-green-200">
                                                {publicKey.seed.substring(0, 40)}...
                                            </div>
                                        </div>

                                        <div className="bg-red-500/20 p-4 rounded-xl border border-red-400/30">
                                            <h3 className="text-red-300 font-semibold text-sm mb-2">Clé Secrète</h3>
                                            <div className="bg-black/40 p-2 rounded text-xs font-mono break-all text-red-200">
                                                {secretKey.seed.substring(0, 40)}...
                                            </div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Sign Tab */}
                        {activeTab === 'sign' && (
                            <div className="space-y-4">
                                <h2 className="text-2xl font-bold text-white">Algorithm 7: Sign</h2>

                                <textarea
                                    value={document}
                                    onChange={(e) => setDocument(e.target.value)}
                                    placeholder="Document à signer..."
                                    className="w-full bg-black/40 text-white p-3 rounded-lg border border-blue-400/30"
                                    rows={6}
                                />

                                <button
                                    onClick={handleSign}
                                    disabled={!expandedSK || !document || isProcessing}
                                    className="w-full bg-gradient-to-r from-purple-500 to-pink-600 text-white py-3 rounded-xl font-semibold flex items-center justify-center gap-2"
                                >
                                    <FileText className="w-5 h-5" />
                                    Signer
                                </button>

                                {signature && (
                                    <div className="bg-purple-500/20 p-4 rounded-xl border border-purple-400/30">
                                        <div className="flex justify-between items-center mb-2">
                                            <h3 className="text-purple-200 font-semibold text-sm">Signature</h3>
                                            <button onClick={() => copyToClipboard(JSON.stringify(signature))}>
                                                <Copy className="w-4 h-4 text-purple-300" />
                                            </button>
                                        </div>
                                        <p className="text-xs text-purple-200">Taille: {signature.size} bytes</p>
                                    </div>
                                )}
                            </div>
                        )}

                        {/* Verify Tab */}
                        {activeTab === 'verify' && (
                            <div className="space-y-4">
                                <h2 className="text-2xl font-bold text-white">Algorithm 8: Verify</h2>

                                <textarea
                                    value={verifyDoc}
                                    onChange={(e) => setVerifyDoc(e.target.value)}
                                    placeholder="Document..."
                                    className="w-full bg-black/40 text-white p-3 rounded-lg"
                                    rows={4}
                                />

                                <textarea
                                    value={verifySignature}
                                    onChange={(e) => setVerifySignature(e.target.value)}
                                    placeholder="Signature JSON..."
                                    className="w-full bg-black/40 text-white p-3 rounded-lg font-mono text-xs"
                                    rows={4}
                                />

                                <button
                                    onClick={handleVerify}
                                    disabled={isProcessing}
                                    className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 text-white py-3 rounded-xl font-semibold flex items-center justify-center gap-2"
                                >
                                    <Shield className="w-5 h-5" />
                                    Vérifier
                                </button>

                                {verificationResult && (
                                    <div className={`p-4 rounded-xl ${
                                        verificationResult.valid
                                            ? 'bg-green-500/20 border-green-400/50'
                                            : 'bg-red-500/20 border-red-400/50'
                                    } border`}>
                                        <div className="flex items-center gap-3">
                                            {verificationResult.valid ? (
                                                <CheckCircle className="w-6 h-6 text-green-300" />
                                            ) : (
                                                <XCircle className="w-6 h-6 text-red-300" />
                                            )}
                                            <span className={`font-bold ${
                                                verificationResult.valid ? 'text-green-200' : 'text-red-200'
                                            }`}>
                        {verificationResult.valid ? 'Signature VALIDE' : 'Signature INVALIDE'}
                      </span>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>

                    {/* Logs Column */}
                    <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-4 border border-white/20">
                        <h3 className="text-white font-bold mb-3 text-sm">Logs</h3>
                        <div className="bg-black/40 rounded-lg p-3 h-[500px] overflow-y-auto">
                            {logs.map((log, idx) => (
                                <div key={idx} className="text-xs font-mono text-gray-300 mb-1">
                                    <span className="text-gray-500">[{log.timestamp}]</span> {log.msg}
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}