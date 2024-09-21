import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.FileReader;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;


public class KeyLoader {

    public static PublicKey loadPublicKeyFromCert(String certPath) throws Exception {
        // Load the X.509 certificate
        FileInputStream fis = new FileInputStream(certPath);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);

        // Extract the public key from the certificate
        return cert.getPublicKey();
    }

    public static PrivateKey loadPrivateKey(String privateKeyPath) throws Exception {
        // Read the private key from the PEM file
        PemReader pemReader = new PemReader(new FileReader(privateKeyPath));
        PemObject pemObject = pemReader.readPemObject();
        byte[] content = pemObject.getContent();
        pemReader.close();

        // Convert the PKCS#1 private key into PKCS#8 format
        RSAPrivateKey rsaPrivateKey = RSAPrivateKey.getInstance(ASN1Primitive.fromByteArray(content));
        PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
                rsaPrivateKey);

        byte[] pkcs8Bytes = privateKeyInfo.getEncoded();

        // Generate a private key from the PKCS#8 key specification
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8Bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }
}