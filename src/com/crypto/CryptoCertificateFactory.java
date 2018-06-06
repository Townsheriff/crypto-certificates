package com.crypto;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.security.cert.X509Certificate;
import java.util.Date;

public class CryptoCertificateFactory {
    private final String keyType;
    private final String algorithm;
    private final int keySize;
    private final int validity;


    public CryptoCertificateFactory(String keyType, int keySize, String algorithm, int validity) {
        this.keyType = keyType;
        this.keySize = keySize;
        this.algorithm = algorithm;
        this.validity = validity;
    }

    public CryptoCertificate createSelfSigned(
            String name,
            String orgUnit,
            String org,
            String city,
            String state,
            String country
    ) {
        CryptoCertificate certificate = null;

        try {
            CertAndKeyGen generator = new CertAndKeyGen(keyType, algorithm);
            generator.generate(keySize);

            X500Name x500Name = new X500Name(name, orgUnit, org, city, state, country);

            X509Certificate x509Certificate = generator.getSelfCertificate(x500Name, new Date(), validity);

            byte[] encPublicKey = generator.getPublicKey().getEncoded();
            byte[] encPrivateKey = generator.getPrivateKey().getEncoded();
            byte[] encCertificate = x509Certificate.getEncoded();

            certificate = new CryptoCertificate(encCertificate, encPublicKey, encPrivateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return certificate;
    }

    public CryptoCertificate loadFromFile(String certPath, String publicKeyPath, String privateKeyPath) {
        CryptoCertificate certificate = null;

        byte[] encPublicKey = FileSystem.readFile(publicKeyPath);
        byte[] encPrivateKey = FileSystem.readFile(privateKeyPath);
        byte[] encCertificate = FileSystem.readFile(certPath);

        if (encCertificate != null && encPrivateKey != null && encPublicKey != null) {
            certificate = new CryptoCertificate(encCertificate, encPublicKey, encPrivateKey);
        }

        return certificate;
    }

    public CryptoCertificate loadFromBytes(byte[] encCertificate, byte[] encPublicKey, byte[] encPrivateKey) {
        CryptoCertificate certificate = null;

        if (encCertificate != null && encPublicKey != null && encPrivateKey != null) {
            certificate = new CryptoCertificate(encCertificate, encPublicKey, encPrivateKey);
        }

        return certificate;
    }
}
