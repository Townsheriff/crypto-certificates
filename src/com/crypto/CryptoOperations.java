package com.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class CryptoOperations {
    private final String keyAlgorithm;
    private final String signAlgorithm;
    private final String certificateType;

    public CryptoOperations(String signAlgorithm, String keyAlgorithm, String certificateType) {
        this.signAlgorithm = signAlgorithm;
        this.keyAlgorithm = keyAlgorithm;
        this.certificateType = certificateType;
    }

    public byte[] encrypt(byte[] encPrivateKey, byte[] inputFile) {
        PrivateKey privateKey = getPrivateKey(encPrivateKey);

        if (privateKey == null) {
            return null;
        }

        try {
            Cipher cipher = Cipher.getInstance(keyAlgorithm);
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return cipher.doFinal(inputFile);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] decrypt(byte[] encCertificate, byte[] inputFile) {
        X509Certificate certificate = getCertificate(encCertificate);

        if (certificate == null) {
            return null;
        }

        try {
            PublicKey publicKey = certificate.getPublicKey();
            Cipher cipher = Cipher.getInstance(keyAlgorithm);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            return cipher.doFinal(inputFile);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
    }

    public boolean isSignatureValid(CryptoContainer container) {
        // initializes loaded certificate
        X509Certificate certificate1 = getCertificate(container.getEncCertificate());

        // creates signature from certificate using private key
        byte[] certSignature = createSignature(container);

        // returns false when failed to do any initiating
        if (certSignature == null || certificate1 == null) {
            return false;
        }

        try {
            Signature signature = Signature.getInstance(signAlgorithm);
            signature.initVerify(certificate1.getPublicKey());
            signature.update(container.getEncCertificate());

            // checks if is root certificate
            boolean isRootCertificate = certificate1.getIssuerDN().equals(certificate1.getSubjectDN());

            // checks if signature is created using private key
            return isRootCertificate && signature.verify(certSignature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return false;
        }
    }

    private byte[] createSignature(CryptoContainer container) {
        PrivateKey privateKey = getPrivateKey(container.getEncPrivateKey());

        if (privateKey == null) {
            return null;
        }

        try {
            Signature signature = Signature.getInstance(signAlgorithm);
            signature.initSign(privateKey);
            signature.update(container.getEncCertificate());
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

    private PrivateKey getPrivateKey(byte[] encPrivateKey) {
        try {
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encPrivateKey);
            KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    private X509Certificate getCertificate(byte[] encCertificate) {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance(certificateType);
            InputStream in = new ByteArrayInputStream(encCertificate);
            return (X509Certificate) certificateFactory.generateCertificate(in);
        } catch (CertificateException e) {
            e.printStackTrace();
            return null;
        }
    }
}
