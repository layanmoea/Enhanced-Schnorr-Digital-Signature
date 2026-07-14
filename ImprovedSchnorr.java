
package improvedschnorr;

// BouncyCastle libraries for cryptography
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

public class ImprovedSchnorr{

    //improved Schnorr Signature
    public static class Schnorr {

        private final ECDomainParameters domainParams;  // Elliptic Curve domain parameters
        private final SecureRandom random = new SecureRandom(); // Random generator

        // Constructor: Initialize secp256k1 curve
        public Schnorr() {
            X9ECParameters params = CustomNamedCurves.getByName("secp256k1");
            this.domainParams = new ECDomainParameters(
                    params.getCurve(),
                    params.getG(),  // Generator point
                    params.getN(),  // Curve order
                    params.getH()   // Cofactor
            );
        }

        //Key Generation
        public KeyPair generateKeyPair() {
            BigInteger n = domainParams.getN();
            BigInteger d;

            // comput d , Random private key in [1, n-1]
            do { 
                d = new BigInteger(n.bitLength(), random); 
            } while (d.signum() == 0 || d.compareTo(n) >= 0);

            // Compute public key Q = d*G
            ECPoint Q = domainParams.getG().multiply(d).normalize();
            return new KeyPair(d, Q);
        }

        //SIGNING
        public Signature sign(byte[] msg, BigInteger d, byte[] aux) {
            BigInteger n = domainParams.getN();

            // Derive deterministic nonce(DRBNG)using HMAC-SHA3
            BigInteger k = deriveNonce(d, msg, aux, n);
            if (k.signum() == 0) // fallback if zero
                k = deriveNonce(d, concat(msg, new byte[]{1}), aux, n); //regenrate k

            // Compute R = k*G
            ECPoint R = domainParams.getG().multiply(k).normalize();
            byte[] Rb = R.getEncoded(true); // Compressed encoding

            // Compute challenge r = H(msg || R || Q)
            byte[] Qb = domainParams.getG().multiply(d).normalize().getEncoded(true);
            BigInteger r = computeChallenge(msg, Rb, Qb, n);

            // Compute s = k + r*d (mod n)
            BigInteger s = k.add(r.multiply(d)).mod(n);

            return new Signature(Rb, s, r);
        }

        //VERIFCATION
        public boolean verify(byte[] msg, ECPoint Q, Signature sig) {
            BigInteger n = domainParams.getN();
            BigInteger r = computeChallenge(msg, sig.Rb, Q.getEncoded(true), n);

            // Reconstruct R' = s*G - r*Q
            ECPoint Rp = domainParams.getG().multiply(sig.s)
                    .subtract(Q.multiply(r))
                    .normalize();

            ECPoint R = domainParams.getCurve().decodePoint(sig.Rb).normalize();

            // Verify R == R'
            return R.equals(Rp);
        }

        //rebuilds R from (s, r, Q)
        public ECPoint reconstructRprime(BigInteger s, BigInteger r, ECPoint Q) {
            return domainParams.getG().multiply(s)
                    .subtract(Q.multiply(r)).normalize();
        }

        //Deterministic Nonce Derivation
        private BigInteger deriveNonce(BigInteger d, byte[] msg, byte[] aux, BigInteger n) {

            // If no auxiliary randomness is provided, use an empty byte array
            if (aux == null) aux = new byte[0];

            // Initialize HMAC with SHA3-256 digest
            HMac hmac = new HMac(new SHA3Digest(256));

            // Use the private key `d` as the HMAC key
            hmac.init(new KeyParameter(d.toByteArray()));

            // Concatenate message and auxiliary randomness for input to HMAC
            byte[] input = concat(msg, aux);

            // Enter the input into HMAC
            hmac.update(input, 0, input.length);

            // Create a buffer to hold the HMAC output
            byte[] out = new byte[hmac.getMacSize()];

            // Compute the HMAC digest into the buffer
            hmac.doFinal(out, 0);

            return new BigInteger(1, out).mod(n);
        }

        //Challenge Computation " r=H(“Schnorr-v1” ∥m∥R_b∥Q_b)mod n "
        private BigInteger computeChallenge(byte[] msg, byte[] Rb, byte[] Qb, BigInteger n) {
            
            byte[] tag = "Schnorr-v1".getBytes(StandardCharsets.UTF_8);
            
            //Concatenate all inputs for hashing
            byte[] data = concat(concat(tag, msg), concat(Rb, Qb));

            //Initialize SHA3-256 hash function
            SHA3Digest digest = new SHA3Digest(256);
            
            //Enter the inputs into HMAC
            digest.update(data, 0, data.length);

           //Prepare buffer to hold the hash output
            byte[] out = new byte[digest.getDigestSize()];
            
            digest.doFinal(out, 0);
            return new BigInteger(1, out).mod(n);
        }

        //Concatenate byte arrays
        private static byte[] concat(byte[] a, byte[] b) {
            byte[] c = new byte[a.length + b.length];
            System.arraycopy(a, 0, c, 0, a.length);
            System.arraycopy(b, 0, c, a.length, b.length);
            return c;
        }

        // Inner class to represent a Schnorr key pair
        public static class KeyPair {
            public BigInteger d;   // Private key
            public ECPoint Q;      // Public key
            public KeyPair(BigInteger d, ECPoint Q) { this.d = d; this.Q = Q; }
        }

        //inner class is a container for a Schnorr digital signature
        public static class Signature {
            public byte[] Rb;      // Encoded R
            public BigInteger s;   // Signature component s
            public BigInteger r;   // Challenge component r
            
            public Signature(byte[] Rb, BigInteger s, BigInteger r) {
                this.Rb = Rb;
                this.s = s;
                this.r = r;
            }
        }
    }

    //converts a byte array into a readable hexadecimal string
    public static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    //MAIN DEMO
    public static void main(String[] args) {

        Schnorr schnorr = new Schnorr();

        //Message
        byte[] msg = "It is an implementation for our improvement schnorr signature".getBytes(StandardCharsets.UTF_8);
        //auxiliary randomness
        byte[] aux = "auxiliary".getBytes();

        //Generate key pair
        Schnorr.KeyPair kp = schnorr.generateKeyPair();

        //Sign and measure timing
        long t1 = System.nanoTime();
        Schnorr.Signature sig = schnorr.sign(msg, kp.d, aux);
        long t2 = System.nanoTime();

        //1) Final Signature
        System.out.println("1) Final Signature = (R_b, s)");
        System.out.println("R_b : " + toHex(sig.Rb));
        System.out.println("s : " + sig.s.toString(16));
        System.out.println();

        //2) Verification Reconstruction
        System.out.println("2) Verification Reconstruction : ");

        BigInteger rPrime = sig.r;
        ECPoint Rprime = schnorr.reconstructRprime(sig.s, rPrime, kp.Q);

        System.out.println("R  (from signature) hex: " + toHex(sig.Rb));
        System.out.println("R' (reconstructed)  hex: " + toHex(Rprime.getEncoded(true)));
        System.out.println("R.equals(R') ? " + Arrays.equals(sig.Rb, Rprime.getEncoded(true)));
        System.out.println();
        
        //3) Timing Demo
        System.out.println("3) Signing took " + (t2 - t1) + " ns (timing demo)");

        //4) Simulated Brute-force Check (This will not find the correct key because the number of checks is too low)
        System.out.println("4) Simulated brute-force check: trying 1000 random keys...");
        boolean found = false;
        SecureRandom rnd = new SecureRandom();
        for (int i = 0; i < 1000; i++) {
            BigInteger guess = new BigInteger(kp.d.bitLength(), rnd);
            if (guess.equals(kp.d)) { found = true; break; }
        }
        System.out.println("Found correct key? " + found);
        System.out.println();
    }
}