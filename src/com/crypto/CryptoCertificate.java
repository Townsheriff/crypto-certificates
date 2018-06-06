package com.crypto;

public class CryptoCertificate {
    private final byte[] certificate;
    private final byte[] publicKey;
    private final byte[] privateKey;

    public CryptoCertificate(byte[] certificate, byte[] publicKey, byte[] privateKey) {
        this.certificate = certificate;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public boolean savePrivateKey(String path) {
        return FileSystem.writeFile(path, this.privateKey);
    }

    public boolean savePublicKey(String path) {
        return FileSystem.writeFile(path, this.publicKey);
    }

    public boolean saveCertificate(String path) {
        return FileSystem.writeFile(path, this.certificate);
    }

    public byte[] getEncCertificate() {
        return certificate;
    }

    public byte[] getEncPublicKey() {
        return publicKey;
    }

    public byte[] getEncPrivateKey() {
        return privateKey;
    }
}
