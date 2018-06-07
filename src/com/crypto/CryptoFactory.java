package com.crypto;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.security.cert.X509Certificate;
import java.util.Date;

public class CryptoFactory {
    private final String keyType;
    private final String algorithm;
    private final int keySize;
    private final int validity;


    public CryptoFactory(String keyType, int keySize, String algorithm, int validity) {
        this.keyType = keyType;
        this.keySize = keySize;
        this.algorithm = algorithm;
        this.validity = validity;
    }

    public CryptoContainer createSelfSignedCertificate(
            String name,
            String orgUnit,
            String org,
            String city,
            String state,
            String country
    ) {
        CryptoContainer container = null;

        try {
            CertAndKeyGen generator = new CertAndKeyGen(keyType, algorithm);
            generator.generate(keySize);

            X500Name x500Name = new X500Name(name, orgUnit, org, city, state, country);

            X509Certificate x509Certificate = generator.getSelfCertificate(x500Name, new Date(), validity);

            byte[] encPublicKey = generator.getPublicKey().getEncoded();
            byte[] encPrivateKey = generator.getPrivateKey().getEncoded();
            byte[] encCertificate = x509Certificate.getEncoded();

            container = new CryptoContainer(encCertificate, encPublicKey, encPrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return container;
    }

    public CryptoContainer loadFromFile(String privateKeyPath, String publicKeyPath, String certPath) {
        CryptoContainer container = null;

        byte[] encPublicKey = FileSystem.readFile(publicKeyPath);
        byte[] encPrivateKey = FileSystem.readFile(privateKeyPath);
        byte[] encCertificate = FileSystem.readFile(certPath);

        if (encCertificate != null && encPrivateKey != null && encPublicKey != null) {
            container = new CryptoContainer(encCertificate, encPublicKey, encPrivateKey);
        }

        return container;
    }

    public CryptoContainer loadPrivateKeyFromFile(String privateKeyPath) {
        CryptoContainer container = null;

        byte[] encPrivateKey = FileSystem.readFile(privateKeyPath);

        if (encPrivateKey != null) {
            container = new CryptoContainer(null, null, encPrivateKey);
        }

        return container;
    }

    public CryptoContainer loadCertificateFromFile(String certPath) {
        CryptoContainer container = null;

        byte[] encCertificate = FileSystem.readFile(certPath);

        if (encCertificate != null) {
            container = new CryptoContainer(encCertificate, null, null);
        }

        return container;
    }
}
