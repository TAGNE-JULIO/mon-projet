export interface MayoParams {
    n: number;
    m: number;
    o: number;
    k: number;
    q: number;
    v: number;
    salt_bytes: number;
    digest_bytes: number;
    pk_seed_bytes: number;
    sk_seed_bytes: number;
    pk_size: number;
    sk_size: number;
    sig_size: number;
    security_level: number;
}

export const MAYO_PARAMS: Record<string, MayoParams> = {
    MAYO_1: {
        n: 86, m: 78, o: 8, k: 10, q: 16,
        v: 78,
        salt_bytes: 24,
        digest_bytes: 32,
        pk_seed_bytes: 16,
        sk_seed_bytes: 24,
        pk_size: 1420,
        sk_size: 24,
        sig_size: 454,
        security_level: 1
    },
    MAYO_2: {
        n: 81, m: 64, o: 17, k: 4, q: 16,
        v: 64,
        salt_bytes: 24,
        digest_bytes: 32,
        pk_seed_bytes: 16,
        sk_seed_bytes: 24,
        pk_size: 4912,
        sk_size: 24,
        sig_size: 186,
        security_level: 1
    },
    MAYO_3: {
        n: 118, m: 108, o: 10, k: 11, q: 16,
        v: 108,
        salt_bytes: 32,
        digest_bytes: 48,
        pk_seed_bytes: 16,
        sk_seed_bytes: 32,
        pk_size: 2986,
        sk_size: 32,
        sig_size: 681,
        security_level: 3
    },
    MAYO_5: {
        n: 154, m: 142, o: 12, k: 12, q: 16,
        v: 142,
        salt_bytes: 40,
        digest_bytes: 64,
        pk_seed_bytes: 16,
        sk_seed_bytes: 40,
        pk_size: 5554,
        sk_size: 40,
        sig_size: 964,
        security_level: 5
    }
};
