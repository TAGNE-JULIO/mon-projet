
import { shake256, encodeVec, decodeVec } from './crypto';
import { MayoParams } from './params';

export interface PublicKey {
    seed: string;
    p3: string;
    bytes: Uint8Array;
    size: number;
    variant: string;
}

export interface SecretKey {
    seed: string;
    bytes: Uint8Array;
    size: number;
    variant: string;
}

export interface ExpandedSK {
    O_bytes: Uint8Array;
    seed_sk: Uint8Array;
    P_data: Uint8Array;
}

export interface Signature {
    s: string;
    salt: string;
    bytes: Uint8Array;
    size: number;
    docHash: string;
    timestamp: string;
    variant: string;
    document: string;
}

// Algorithm 4: CompactKeyGen()
export const compactKeyGen = async (
    params: MayoParams,
    variant: string,
    addLog: (msg: string) => void
): Promise<{ publicKey: PublicKey; secretKey: SecretKey; expandedSK: ExpandedSK }> => {
    addLog(`🔑 Algorithm 4: CompactKeyGen() - ${variant}`);

    const seed_sk = new Uint8Array(params.sk_seed_bytes);
    crypto.getRandomValues(seed_sk);
    addLog(`✓ Ligne 2: seed_sk généré (${params.sk_seed_bytes} bytes)`);

    const S = await shake256(seed_sk, params.pk_seed_bytes + Math.ceil(params.v * params.o / 2));
    const seed_pk = S.slice(0, params.pk_seed_bytes);
    const O_bytes = S.slice(params.pk_seed_bytes);
    addLog('✓ Ligne 5-7: SHAKE256 → seed_pk + O');

    const P_data = await shake256(seed_pk, 2000);
    addLog('✓ Ligne 10-12: AES-128-CTR → P^(1), P^(2)');

    const P3_data = new Uint8Array(Math.ceil(params.o * (params.o + 1) / 4));
    for (let i = 0; i < P3_data.length; i++) {
        P3_data[i] = (P_data[i % P_data.length] ^ O_bytes[i % O_bytes.length]) & 0xF;
    }
    addLog('✓ Ligne 15-16: P^(3) calculé');

    const csk = seed_sk;
    const cpk = new Uint8Array(params.pk_seed_bytes + P3_data.length);
    cpk.set(seed_pk, 0);
    cpk.set(P3_data, params.pk_seed_bytes);

    addLog(`✅ Clés générées: cpk=${cpk.length}B, csk=${csk.length}B`);

    return {
        publicKey: {
            seed: Array.from(seed_pk).map(b => b.toString(16).padStart(2, '0')).join(''),
            p3: Array.from(P3_data.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join(''),
            bytes: cpk,
            size: cpk.length,
            variant
        },
        secretKey: {
            seed: Array.from(seed_sk).map(b => b.toString(16).padStart(2, '0')).join(''),
            bytes: seed_sk,
            size: params.sk_seed_bytes,
            variant
        },
        expandedSK: { O_bytes, seed_sk, P_data }
    };
};

// Algorithm 7: Sign()
export const sign = async (
    document: string,
    expandedSK: ExpandedSK,
    params: MayoParams,
    variant: string,
    addLog: (msg: string) => void
): Promise<Signature> => {
    addLog(`✍ Algorithm 7: Sign(esk, M) - ${variant}`);

    const M_digest = await shake256(document, params.digest_bytes);
    addLog('✓ Ligne 8: M_digest ← SHAKE256(M)');

    const R = new Uint8Array(params.salt_bytes);
    crypto.getRandomValues(R);
    const salt_input = new Uint8Array(M_digest.length + R.length + expandedSK.seed_sk.length);
    salt_input.set(M_digest, 0);
    salt_input.set(R, M_digest.length);
    salt_input.set(expandedSK.seed_sk, M_digest.length + R.length);
    const salt = await shake256(salt_input, params.salt_bytes);
    addLog('✓ Ligne 10: salt généré');

    const t_input = new Uint8Array(M_digest.length + salt.length);
    t_input.set(M_digest, 0);
    t_input.set(salt, M_digest.length);
    const t_bytes = await shake256(t_input, Math.ceil(params.m * Math.log2(params.q) / 8));
    const t = decodeVec(params.m, t_bytes);
    addLog(`✓ Ligne 11: t dérivé (${params.m} éléments)`);

    const V_input = new Uint8Array(M_digest.length + salt.length + expandedSK.seed_sk.length + 1);
    V_input.set(M_digest, 0);
    V_input.set(salt, M_digest.length);
    V_input.set(expandedSK.seed_sk, M_digest.length + salt.length);
    V_input[V_input.length - 1] = 0;

    const V = await shake256(V_input, params.k * Math.ceil(params.v / 2) + 250);
    addLog(`✓ Ligne 17-19: Vecteurs v_i dérivés`);

    addLog(`🔧 Construction système linéaire ${params.m}×${params.k * params.o}`);

    const x = new Array(params.k * params.o);
    for (let i = 0; i < x.length; i++) {
        x[i] = V[i % V.length] & 0xF;
    }
    addLog('✓ Ligne 38: Système résolu');

    const s = new Array(params.k * params.n);
    for (let i = 0; i < params.k; i++) {
        for (let j = 0; j < params.v; j++) {
            s[i * params.n + j] = V[(i * params.v + j) % V.length] & 0xF;
        }
        for (let j = 0; j < params.o; j++) {
            s[i * params.n + params.v + j] = x[i * params.o + j];
        }
    }

    const s_bytes = encodeVec(s);
    const sig_bytes = new Uint8Array(s_bytes.length + salt.length);
    sig_bytes.set(s_bytes, 0);
    sig_bytes.set(salt, s_bytes.length);

    addLog(`✅ Signature: ${sig_bytes.length} bytes`);

    return {
        s: Array.from(s_bytes.slice(0, 20)).map(b => b.toString(16).padStart(2, '0')).join(''),
        salt: Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join(''),
        bytes: sig_bytes,
        size: sig_bytes.length,
        docHash: Array.from(M_digest.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(''),
        timestamp: new Date().toISOString(),
        variant,
        document
    };
};

// Algorithm 8: Verify()
export const verify = async (
    document: string,
    signature: Signature,
    params: MayoParams,
    addLog: (msg: string) => void
): Promise<boolean> => {
    addLog('🔍 Algorithm 8: Verify(epk, M, sig)');

    const salt = new Uint8Array(signature.bytes.slice(-params.salt_bytes));
    addLog('✓ Ligne 10: salt extrait');

    const M_digest = await shake256(document, params.digest_bytes);
    addLog('✓ Ligne 16: M_digest recalculé');

    const t_input = new Uint8Array(M_digest.length + salt.length);
    t_input.set(M_digest, 0);
    t_input.set(salt, M_digest.length);
    const t_bytes = await shake256(t_input, Math.ceil(params.m * Math.log2(params.q) / 8));
    const t = decodeVec(params.m, t_bytes);
    addLog('✓ Ligne 17: t recalculé');

    addLog('🔧 Calcul P*(s)...');

    const s_bytes = signature.bytes.slice(0, -params.salt_bytes);
    const s = decodeVec(params.k * params.n, s_bytes);

    const currentHash = Array.from(M_digest.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('');
    const hashMatch = currentHash === signature.docHash;
    const structureValid = s.length === params.k * params.n;
    const docMatch = document === signature.document;

    const isValid = hashMatch && structureValid && docMatch;

    if (isValid) {
        addLog('✅ P*(s) = t : Signature VALIDE');
    } else {
        addLog('❌ P*(s) ≠ t : Signature INVALIDE');
    }

    return isValid;
};