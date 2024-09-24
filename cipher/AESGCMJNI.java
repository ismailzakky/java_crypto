import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AESGCMJNI {


    public static void main(String args[]) {

        String ivString = "fTKhk/OoK/IBVcq/i1C02jmRuvEzGU8J1UypKJaGiidZ+oWXkNE4wrhsVgEE2tVFkX2A6iSqFxK/JtMrmTSsEpNJ/ZTMZrZeyNqJHAMWqVISRappo6HPowWXLtQuUIOH";
        String encryptedTextString = "Mgqx8Xs/7/lHdyvO5g8fFjfSdnT2qUkVxQeexAludBH2ZbPncUAYlPFDTiOm4l2Q4loeYmYM2UWEKSVHveVfQfhNY3IuH3L51bGTu7kHZxOBlkeDtAx8jkdVg96Vsz7jwh15uMe4DB69iPAhlBfJ0ICCgxsXfEJClUe1wt5B4g+7d3TdfbBLzdSTNfRGRkkPHA73Fk2UaFuo2xDXdSwkapqTWOJcr9Veq8vMoPezyJLL3LshRdVxGx/lmEKJ3kFkwYqg7lzDrDEqlvt7y2vfV2FMqzRY5UF0YTjoOThB3GkAGFT0JySEThKpS66FH+0RR6MKKQwCmCnv7kJ71JViMWkRFvN7CaE+SXCCzpP8hMnDGx15eZ0/IxYlWm9TGixXSPCAyRqF4jXeAYay0nTSKZdmyJwYpyDwpMcAyvG1DBiDUJtkGeNoKbStiaGCZy0QdyHXDWcnE+l8mD/jyV16+CoqAjKhMIyiSyXHzd2V91Cnw7jmOGmQQgATn3Uvw8G+uvfgM7tNORtgWQzWGax4yE5Z7B5WjlMzyoQR1u886/Tp+LKHEn3EXO+5g5kk9GZBzFLvIIlMFcPSNSSdjh5LDT9MkbT0IxcA3N3w0RKSZmTtBvXM1i1dyzk25X0nG24/OqsbUZiwKz8O9ZSvf5p6ujHZX0zO2+pwkWxdDEYoupRHqky0u25wl8QFPaI4+tvbJ41pP24ErAS9yzSMygYkJPJrXgUeMwA1RmD1kVVxG1a0hbK4Z2Qz1HP5PlvMbfwo4b4eY6KITJVMGp28ZC/3/HLzxl+2JOJxgfrYMP5IE5HtRh7BowPtI6LT8v1WIfi+y5sm84AbFZhwcD7I3yePpX7oC+qvw/zG2n8ZZgFtPkEakdSODf8IEiQ3C9QdNKs5fGUXc2IFZa6MseT1SeeCmJanZ7eCTvDvX/rRk9aET8ATrLNoYpxo";
        String aadData = "pay-staging.tokopedia.com";
        String aesKeyString = "VaEKpL9jLJCZdMCKzjKHu8ROfjE9cKRQOi+JIA92kO0=";

        String decryptedPayload;

        decryptedPayload = decrypt(ivString,encryptedTextString,aesKeyString,aadData);
        System.out.println(decryptedPayload);

    }

    public static String decrypt(String ivString, String encryptedTextString, String aesKeyString, String aadData) {
        try {
            // Decode Base64-encoded inputs
            byte[] iv = Base64.getDecoder().decode(ivString);
            byte[] encryptedText = Base64.getDecoder().decode(encryptedTextString);
            byte[] aesKeyBytes = Base64.getDecoder().decode(aesKeyString);

            // Recreate SecretKey
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            // Initialize GCM Parameters
            GCMParameterSpec gcmParamSpec = new GCMParameterSpec(128, iv);

            // Decrypt
            Cipher cipher = Cipher.getInstance("AES/GCM/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmParamSpec);
            cipher.updateAAD(aadData.getBytes());

            return new String(cipher.doFinal(encryptedText));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
