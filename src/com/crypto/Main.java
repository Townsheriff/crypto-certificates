package com.crypto;

import java.util.Arrays;

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

    private static final String CREATE_ACTION = "create";
    private static final String VERIFY_ACTION = "verify";
    private static final String ENCRYPT_ACTION = "encrypt";
    private static final String DECRYPT_ACTION = "decrypt";

    public static void main(String[] args) {
        CryptoFactory certificateFactory = new CryptoFactory(
                KEY_ALGORITHM,
                KEY_SIZE,
                SIGNATURE_ALGORITHM,
                VALIDITY
        );

        CryptoOperations operations = new CryptoOperations(
                SIGNATURE_ALGORITHM,
                KEY_ALGORITHM,
                CERTIFICATE_TYPE
        );

        if (args.length < 1) {
            printHelp();
            return;
        }

        Main main = new Main(certificateFactory, operations);

        String[] mainArgs = new String[0];
        if (args.length > 1) { // throws error when args size is 1
            mainArgs = Arrays.copyOfRange(args, 1, args.length);
        }

        switch (args[0]) {
            case CREATE_ACTION:
                main.createCertificate(mainArgs);
                return;
            case VERIFY_ACTION:
                main.verifyCertificate(mainArgs);
                return;
            case ENCRYPT_ACTION:
                main.encryptMessage(mainArgs);
                return;
            case DECRYPT_ACTION:
                main.decryptMessage(mainArgs);
                return;
            default:
                printHelp();
        }
    }

    private static void printHelp() {
        System.out.println("Allowed commands:");
        System.out.println("app create [option [, ...]] - to create a self signed certificate");
        System.out.println("app verify [option [, ...]] - to verify a certificate");
        System.out.println("app encrypt [option [, ...]] - to encrypt a file with private key");
        System.out.println("app decrypt [option [, ...]] - to decrypt a file with public key");
    }

    private final CryptoFactory certificateFactory;
    private final CryptoOperations cryptoOperations;

    public Main(CryptoFactory certificateFactory, CryptoOperations cryptoOperations) {
        this.certificateFactory = certificateFactory;
        this.cryptoOperations = cryptoOperations;
    }

    private void createCertificate(String[] args) {
        if (args.length < 4) {
            System.out.println("To create certificate required 4 arguments:");
            System.out.println("1 - output path for private key");
            System.out.println("2 - output path for public key");
            System.out.println("3 - output path for certificate");
            System.out.println("4 - input path for certificate options");
            return;
        }

        String privateKeyPath = args[0];
        String publicKeyPath = args[1];
        String certificatePath = args[2];
        String optionsPath = args[3];

        String certificateOptions = FileSystem.readFileAsString(optionsPath);

        if (certificateOptions == null) {
            System.out.println("Certificate options are not correctly provided");
            return;
        }

        String[] certificateArrayOptions = certificateOptions.split("\n");

        if (certificateArrayOptions.length < 5) {
            System.out.println("Certificate options require 6 lines in a file");
            return;
        }

        CryptoContainer container = certificateFactory.createSelfSignedCertificate(
                certificateArrayOptions[0], // name
                certificateArrayOptions[1], // orgUnit
                certificateArrayOptions[2], // org
                certificateArrayOptions[3], // city
                certificateArrayOptions[4], // state
                certificateArrayOptions[5]  // country
        );

        if (container == null) {
            System.out.println("Failed to create self signed certificate");
            return;
        }

        boolean isSavedToDisk = container.saveCertificate(certificatePath);

        if (!isSavedToDisk) {
            System.out.println("Failed to save certificate to disk");
        }

        isSavedToDisk = container.savePrivateKey(privateKeyPath);

        if (!isSavedToDisk) {
            System.out.println("Failed to save private key to disk");
        }


        isSavedToDisk = container.savePublicKey(publicKeyPath);

        if (!isSavedToDisk) {
            System.out.println("Failed to save public key to disk");
        }
    }

    private void verifyCertificate(String[] args) {
        if (args.length < 3) {
            System.out.println("To verify certificate required 3 arguments:");
            System.out.println("1 - input path to private key");
            System.out.println("2 - input path to public key");
            System.out.println("3 - input path to certificate");
            return;
        }

        CryptoContainer container = certificateFactory.loadFromFile(
                args[0], // private key path
                args[1], // public key path
                args[2]  // certificate path
        );

        if (container == null) {
            System.out.println("Failed to load certificate from disk");
        }

        boolean isValid = cryptoOperations.isSignatureValid(container);

        if (isValid) {
            System.out.println("Certificate signature is valid");
        } else {
            System.out.println("Certificate signature is NOT valid");
        }
    }

    private void encryptMessage(String[] args) {
        if (args.length < 3) {
            System.out.println("To encrypt certificate required 2 arguments:");
            System.out.println("1 - input path to private key");
            System.out.println("2 - input path to certificate");
            System.out.println("3 - input path for file to encrypt");
            System.out.println("4 - output path for encrypted file");
            return;
        }

        CryptoContainer container = certificateFactory.loadPrivateKeyFromFile(
                args[0] // private key path
        );

        byte[] inputFile = FileSystem.readFile(args[1]);

        if (inputFile == null) {
            System.out.println("Failed to target file from disk");
            return;
        }

        if (container == null) {
            System.out.println("Failed to load certificate from disk");
            return;
        }

        byte[] outputFile = cryptoOperations.encrypt(container.getEncPrivateKey(), inputFile);

        if (outputFile == null) {
            System.out.println("Failed to encrypt file");
            return;
        }

        boolean isSavedToDisk = FileSystem.writeFile(args[2], outputFile);

        if (!isSavedToDisk) {
            System.out.println("Failed saving file to disk");
        }
    }

    private void decryptMessage(String[] args) {
        if (args.length < 3) {
            System.out.println("To decrypt certificate required 2 arguments:");
            System.out.println("1 - input path to public key");
            System.out.println("2 - input path for encrypted file");
            System.out.println("3 - output path for decrypted file");
            return;
        }

        CryptoContainer container = certificateFactory.loadCertificateFromFile(
                args[0] // public key path
        );

        byte[] inputFile = FileSystem.readFile(args[1]);

        if (inputFile == null) {
            System.out.println("Failed to target file from disk");
            return;
        }

        if (container == null) {
            System.out.println("Failed to load certificate from disk");
            return;
        }

        byte[] outputFile = cryptoOperations.decrypt(container.getEncCertificate(), inputFile);

        if (outputFile == null) {
            System.out.println("Failed to encrypt file");
            return;
        }

        boolean isSavedToDisk = FileSystem.writeFile(args[2], outputFile);

        if (!isSavedToDisk) {
            System.out.println("Failed saving file to disk");
        }
    }
}
