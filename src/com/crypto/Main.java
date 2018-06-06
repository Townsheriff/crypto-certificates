package com.crypto;

import java.util.Arrays;
import java.util.Calendar;

/**
 * enable asserts - "-ea" https://docs.oracle.com/cd/E19683-01/806-7930/assert-4/index.html
 * homework - https://estudijas.lu.lv/pluginfile.php/279475/mod_assign/intro/hw2_2018.pdf
 * tutorials - https://docs.oracle.com/javase/tutorial/security/apisign/step2.html
 * some docs - https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyFactory
 * examples - https://www.programcreek.com/java-api-examples/?api=sun.security.tools.keytool.CertAndKeyGen
 */
public class Main {

    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256WithRSA";
    private static final String CERTIFICATE_TYPE = "X.509";
    private static final int KEY_SIZE = 2048;
    private static final int VALIDITY = 1096 * 24 * 60 * 60;

    private static final String CERTIFICATE_PATH = "certificate.cer";
    private static final String PRIVATE_KEY_PATH = "privateKey";
    private static final String PUBLIC_KEY_PATH = "publicKey.pub";

    public static void main(String[] args) {
        CryptoCertificateFactory certificateFactory = new CryptoCertificateFactory(
                KEY_ALGORITHM,
                KEY_SIZE,
                SIGNATURE_ALGORITHM,
                VALIDITY
        );

        CryptoCertificateOperations operations = new CryptoCertificateOperations(
                SIGNATURE_ALGORITHM,
                KEY_ALGORITHM,
                CERTIFICATE_TYPE
        );


        // CREATES SELF SIGNED CERTIFICATE AND WRITES IT TO DISK
        CryptoCertificate selfSignedCert = certificateFactory.createSelfSigned(
                "Arturs",
                "crypto",
                "University of Latvia",
                "Riga",
                "Latvia",
                "Latvia"
        );

        if (selfSignedCert == null) {
            log("Failed to create self signed certificate");
            return;
        }

        boolean isSavedToDisk = selfSignedCert.saveCertificate(CERTIFICATE_PATH);

        if (!isSavedToDisk) {
            log("Failed to save certificate to disk");
        }

        isSavedToDisk = selfSignedCert.savePrivateKey(PRIVATE_KEY_PATH);

        if (!isSavedToDisk) {
            log("Failed to save private key to disk");
        }


        isSavedToDisk = selfSignedCert.savePublicKey(PUBLIC_KEY_PATH);

        if (!isSavedToDisk) {
            log("Failed to save public key to disk");
        }

        // READS SAME CERTIFICATE FROM DISK AND RECREATES CERTIFICATE OBJECT
        CryptoCertificate certFromDisk = certificateFactory.loadFromFile(
                CERTIFICATE_PATH,
                PUBLIC_KEY_PATH,
                PRIVATE_KEY_PATH
        );

        if (certFromDisk == null) {
            log("Failed to load certificate from disk");
        }

        assert certFromDisk != null;

        assert Arrays.equals(selfSignedCert.getEncCertificate(), certFromDisk.getEncCertificate());
        assert Arrays.equals(selfSignedCert.getEncPublicKey(), certFromDisk.getEncPublicKey());
        assert Arrays.equals(selfSignedCert.getEncPrivateKey(), certFromDisk.getEncPrivateKey());

        // VALIDATES THAT SIGNATURE IS VALID
        boolean isValid = operations.isSignatureValid(certFromDisk);

        if (!isValid) {
            log("Disk certificate signature is not valid");
        }

        isValid = operations.isSignatureValid(selfSignedCert);

        if (!isValid) {
            log("Self signed certificate signature is not valid");
        }


        // VALIDATES THAT SIGNATURE IS INVALID
        CryptoCertificate selfSignedCert2 = certificateFactory.createSelfSigned(
                "Arturs",
                "crypto",
                "University of Latvia",
                "Riga",
                "Latvia",
                "Latvia"
        );

        CryptoCertificate invalidCertificate = certificateFactory.loadFromBytes(
                selfSignedCert.getEncCertificate(),
                selfSignedCert2.getEncPublicKey(),
                selfSignedCert.getEncPrivateKey()
        );

        isValid = operations.isSignatureValid(invalidCertificate);

        if (isValid) {
            log("Invalid certificate signature is valid");
        }


        // VALIDATES PUBLIC KEY IN CERTIFICATE
        isValid = operations.isCorrectPublicKey(selfSignedCert);

        if (!isValid) {
            log("Correct certificate does not contain valid public key");
        }

        isValid = operations.isCorrectPublicKey(invalidCertificate);

        if (isValid) {
            log("Invalid certificate contains valid public key");
        }


        // VALIDATES NAME IN CERTIFICATE
        isValid = operations.isRootCertificate(certFromDisk);

        if (!isValid) {
            log("Contains invalid name");
        }
    }

    private static void log(String message) {
        Calendar calendar = Calendar.getInstance();

        String time = calendar.get(Calendar.HOUR) + ":" +
                calendar.get(Calendar.MINUTE) + ":" +
                calendar.get(Calendar.SECOND);

        System.out.println(time + ": " + message);
    }
}
