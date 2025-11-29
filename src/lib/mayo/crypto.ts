export class F16 {
    value: number;

    constructor(value: number) {
        this.value = value & 0xF;
    }

    add(other: F16): F16 {
        return new F16(this.value ^ other.value);
    }

    mul(other: F16): F16 {
        let a = this.value;
        let b = other.value;
        let p = 0;
        for (let i = 0; i < 4; i++) {
            if (b & 1) p ^= a;
            let hi_bit = a & 0x8;
            a = (a << 1) & 0xF;
            if (hi_bit) a ^= 0x3;
            b >>= 1;
        }
        return new F16(p);
    }

    toString(): string {
        return this.value.toString(16);
    }
}

export const shake256 = async (input: string | Uint8Array, outputLength: number): Promise<Uint8Array> => {
    const encoder = new TextEncoder();
    let data: Uint8Array;

    if (input instanceof Uint8Array) {
        data = input;
    } else {
        data = encoder.encode(input);
    }

    const hash = await crypto.subtle.digest('SHA-256', data);
    const hashArray = new Uint8Array(hash);

    const result = new Uint8Array(outputLength);
    for (let i = 0; i < outputLength; i++) {
        result[i] = hashArray[i % hashArray.length] ^ (i >> 3);
    }
    return result;
};

export const encodeVec = (vec: number[]): Uint8Array => {
    const bytes = new Uint8Array(Math.ceil(vec.length / 2));
    for (let i = 0; i < vec.length; i += 2) {
        const nibble1 = vec[i] & 0xF;
        const nibble2 = i + 1 < vec.length ? vec[i + 1] & 0xF : 0;
        bytes[Math.floor(i / 2)] = nibble1 | (nibble2 << 4);
    }
    return bytes;
};

export const decodeVec = (n: number, bytes: Uint8Array): number[] => {
    const vec = new Array(n);
    for (let i = 0; i < n; i++) {
        const byteIdx = Math.floor(i / 2);
        vec[i] = (i % 2 === 0) ? (bytes[byteIdx] & 0xF) : (bytes[byteIdx] >> 4);
    }
    return vec;
};

export const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
};
