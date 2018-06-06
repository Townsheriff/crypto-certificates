package com.crypto;

import java.io.*;

public class FileSystem {
    public static boolean writeFile(String path, byte[] data) {
        try (FileOutputStream stream = new FileOutputStream(path)) {
            stream.write(data);
            return true;
        } catch (java.io.IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static byte[] readFile(String path) {
        try {
            File file = new File(path);
            long fileLength = file.length();

            if (fileLength > Integer.MAX_VALUE) {
                throw new FileSystemException("File length exceeds int max value");
            }

            byte[] output = new byte[(int) fileLength];
            FileInputStream inputStream = new FileInputStream(file);

            if (inputStream.read(output) == -1) {
                throw new FileSystemException("There is no more data because the end of the file has been reached");
            }

            return output;
        } catch (IOException | FileSystemException e) {
            e.printStackTrace();
            return null;
        }
    }


    private static class FileSystemException extends java.lang.Exception {
        public FileSystemException(String message) {
            super(message);
        }
    }
}
