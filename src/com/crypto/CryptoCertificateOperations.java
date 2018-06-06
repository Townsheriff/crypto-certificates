package com.crypto;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class CryptoCertificateOperations {
    private final String keyAlgorithm;
    private final String signAlgorithm;
    private final String certificateType;

    public CryptoCertificateOperations(String signAlgorithm, String keyAlgorithm, String certificateType) {
        this.signAlgorithm = signAlgorithm;
        this.keyAlgorithm = keyAlgorithm;
        this.certificateType = certificateType;
    }

    public boolean isSignatureValid(CryptoCertificate certificate) {
        PublicKey publicKey = getPublicKey(certificate.getEncPublicKey());
        byte[] signedData = createSignature(certificate);

        if (publicKey == null || signedData == null) {
            return false;
        }

        try {
            Signature signature = Signature.getInstance(signAlgorithm);
            signature.initVerify(publicKey);
            signature.update(certificate.getEncCertificate());
            return signature.verify(signedData);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean isCorrectPublicKey(CryptoCertificate certificate) {
        X509Certificate x509Certificate = getCertificate(certificate.getEncCertificate());

        if (x509Certificate == null) {
            return false;
        }

        byte[] encPublicKey = x509Certificate.getPublicKey().getEncoded();
        return Arrays.equals(encPublicKey, certificate.getEncPublicKey());
    }

    public boolean isRootCertificate(CryptoCertificate certificate) {
        X509Certificate x509Certificate = getCertificate(certificate.getEncCertificate());

        if (x509Certificate == null) {
            return false;
        }

        return x509Certificate.getIssuerDN().equals(x509Certificate.getSubjectDN());
    }

    private byte[] createSignature(CryptoCertificate certificate) {
        PrivateKey privateKey = getPrivateKey(certificate.getEncPrivateKey());

        if (privateKey == null) {
            return null;
        }

        try {
            Signature signature = Signature.getInstance(signAlgorithm);
            signature.initSign(privateKey);
            signature.update(certificate.getEncCertificate());
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

    private PublicKey getPublicKey(byte[] encPublicKey) {
        try {
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encPublicKey);
            KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
            return keyFactory.generatePublic(publicKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
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
