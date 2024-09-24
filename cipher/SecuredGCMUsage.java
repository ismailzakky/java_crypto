import javax.crypto.Cipher ;
import java.security.SecureRandom ;
import javax.crypto.spec.GCMParameterSpec ;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.util.Base64 ;

import java.security.NoSuchAlgorithmException ;
import java.security.InvalidKeyException;
import javax.crypto.IllegalBlockSizeException ;
import javax.crypto.NoSuchPaddingException ;
import java.security.InvalidAlgorithmParameterException ;
import javax.crypto.BadPaddingException ;
import javax.crypto.ShortBufferException;

import java.util.Arrays ;

public class SecuredGCMUsage {

    public static int AES_KEY_SIZE = 256 ;
    public static int IV_SIZE = 96 ;
    public static int TAG_BIT_LENGTH = 128 ;
    public static String ALGO_TRANSFORMATION_STRING = "AES/GCM/PKCS5Padding" ;  // Changed padding scheme to NoPadding

    public static void main(String args[]) {
        // Parameters provided in the request
        String ivString = "fTKhk/OoK/IBVcq/i1C02jmRuvEzGU8J1UypKJaGiidZ+oWXkNE4wrhsVgEE2tVFkX2A6iSqFxK/JtMrmTSsEpNJ/ZTMZrZeyNqJHAMWqVISRappo6HPowWXLtQuUIOH";
        String encryptedTextString = "Mgqx8Xs/7/lHdyvO5g8fFjfSdnT2qUkVxQeexAludBH2ZbPncUAYlPFDTiOm4l2Q4loeYmYM2UWEKSVHveVfQfhNY3IuH3L51bGTu7kHZxOBlkeDtAx8jkdVg96Vsz7jwh15uMe4DB69iPAhlBfJ0ICCgxsXfEJClUe1wt5B4g+7d3TdfbBLzdSTNfRGRkkPHA73Fk2UaFuo2xDXdSwkapqTWOJcr9Veq8vMoPezyJLL3LshRdVxGx/lmEKJ3kFkwYqg7lzDrDEqlvt7y2vfV2FMqzRY5UF0YTjoOThB3GkAGFT0JySEThKpS66FH+0RR6MKKQwCmCnv7kJ71JViMWkRFvN7CaE+SXCCzpP8hMnDGx15eZ0/IxYlWm9TGixXSPCAyRqF4jXeAYay0nTSKZdmyJwYpyDwpMcAyvG1DBiDUJtkGeNoKbStiaGCZy0QdyHXDWcnE+l8mD/jyV16+CoqAjKhMIyiSyXHzd2V91Cnw7jmOGmQQgATn3Uvw8G+uvfgM7tNORtgWQzWGax4yE5Z7B5WjlMzyoQR1u886/Tp+LKHEn3EXO+5g5kk9GZBzFLvIIlMFcPSNSSdjh5LDT9MkbT0IxcA3N3w0RKSZmTtBvXM1i1dyzk25X0nG24/OqsbUZiwKz8O9ZSvf5p6ujHZX0zO2+pwkWxdDEYoupRHqky0u25wl8QFPaI4+tvbJ41pP24ErAS9yzSMygYkJPJrXgUeMwA1RmD1kVVxG1a0hbK4Z2Qz1HP5PlvMbfwo4b4eY6KITJVMGp28ZC/3/HLzxl+2JOJxgfrYMP5IE5HtRh7BowPtI6LT8v1WIfi+y5sm84AbFZhwcD7I3yePpX7oC+qvw/zG2n8ZZgFtPkEakdSODf8IEiQ3C9QdNKs5fGUXc2IFZa6MseT1SeeCmJanZ7eCTvDvX/rRk9aET8ATrLNoYpxo";
        String aadData = "pay-staging.tokopedia.com";
        String aesKeyString = "VaEKpL9jLJCZdMCKzjKHu8ROfjE9cKRQOi+JIA92kO0=";

        // Decode the base64-encoded inputs
        byte[] iv = Base64.getDecoder().decode(ivString);
        byte[] encryptedText = Base64.getDecoder().decode(encryptedTextString);
        byte[] aesKeyBytes = Base64.getDecoder().decode(aesKeyString);

        // Recreate the SecretKey from the decoded key bytes
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // Initialize GCM Parameters
        GCMParameterSpec gcmParamSpec = new GCMParameterSpec(TAG_BIT_LENGTH, iv);

        // Decrypt the encrypted text
        byte[] decryptedText = aesDecrypt(encryptedText, aesKey, gcmParamSpec, aadData.getBytes());

        System.out.println("Decrypted text: " + new String(decryptedText));
    }

    public static byte[] aesDecrypt(byte[] encryptedMessage, SecretKey aesKey, GCMParameterSpec gcmParamSpec, byte[] aadData) {
        Cipher c = null;

        try {
            c = Cipher.getInstance(ALGO_TRANSFORMATION_STRING); // Transformation specifies algorithm, mode of operation, and padding
        } catch(NoSuchAlgorithmException | NoSuchPaddingException e) {
            System.out.println("Exception while decrypting: " + e);
            System.exit(1);
        }

        try {
            c.init(Cipher.DECRYPT_MODE, aesKey, gcmParamSpec, new SecureRandom());
        } catch(InvalidKeyException | InvalidAlgorithmParameterException e) {
            System.out.println("Exception while decrypting: " + e);
            System.exit(1);
        }

        try {
            c.updateAAD(aadData); // Add AAD details before decrypting
        } catch(IllegalArgumentException | IllegalStateException e) {
            System.out.println("Exception thrown while decrypting: " + e);
            System.exit(1);
        }

        byte[] plainTextInByteArr = null;
        try {
            plainTextInByteArr = c.doFinal(encryptedMessage);
        } catch(IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Exception while decrypting: " + e);
            System.exit(1);
        }

        return plainTextInByteArr;
    }
}
