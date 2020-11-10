package ua.nat.maxx.hserver.cert;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class CertManager {

    private static final String CA_CERT_NAME = "Max CA";
    private static final String CA_ISSUER_NANE = "Max test certs issuer";
    private static final String CA_FILE_NAME = "max-test-store.pfx";
    char[] emptyPassword = new String("changeit").toCharArray();
    private KeyStore keyStore;
    private GeneratedCert rootCA;
    private GeneratedCert issuer;


    public CertManager() {
        try {
            this.keyStore = KeyStore.getInstance("PKCS12");
        } catch (Exception e) {

        }
        loadKeyStore();
    }

    public void loadKeyStore() {
        try (FileInputStream store = new FileInputStream(CA_FILE_NAME)) {
            keyStore.load(store, emptyPassword);
            rootCA = new GeneratedCert((PrivateKey) keyStore.getKey(CA_CERT_NAME, emptyPassword), (X509Certificate) keyStore.getCertificate(CA_CERT_NAME));
            issuer = new GeneratedCert((PrivateKey) keyStore.getKey(CA_ISSUER_NANE, emptyPassword), (X509Certificate) keyStore.getCertificate(CA_ISSUER_NANE));
        } catch (FileNotFoundException e) {
            initKeyStore();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    private void initKeyStore() {
        try {
            keyStore.load(null, emptyPassword);
            rootCA = createCertificate(CA_CERT_NAME,   /*domain=*/null,     /*issuer=*/null,  /*isCa=*/true);
            issuer = createCertificate(CA_ISSUER_NANE, /*domain=*/null, rootCA,           /*isCa=*/true);
            keyStore.setKeyEntry(CA_CERT_NAME, rootCA.privateKey, emptyPassword, new X509Certificate[]{rootCA.certificate});
            //keyStore.setCertificateEntry(CA_CERT_NAME, rootCA.certificate);
            keyStore.setKeyEntry(CA_ISSUER_NANE, issuer.privateKey, emptyPassword, new X509Certificate[]{issuer.certificate});
            //keyStore.setCertificateEntry(CA_ISSUER_NANE, issuer.certificate);
            try (FileOutputStream store = new FileOutputStream(CA_FILE_NAME)) {
                keyStore.store(store, emptyPassword);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public GeneratedCert issueCertificate(String cnName) {
        try {
            Certificate storeCert = keyStore.getCertificate(cnName);
            PrivateKey key = (PrivateKey) keyStore.getKey(cnName, emptyPassword);
            if (storeCert != null && key != null) {
                return new GeneratedCert(key, (X509Certificate) storeCert);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            GeneratedCert cert = createCertificate(cnName, cnName, issuer, false);
            keyStore.setKeyEntry(cnName, cert.privateKey, emptyPassword, new X509Certificate[]{cert.certificate, issuer.certificate, rootCA.certificate});
            try (FileOutputStream store = new FileOutputStream(CA_FILE_NAME)) {
                keyStore.store(store, emptyPassword);
            }
            return cert;
        } catch (Exception e) {

        }
        throw new IllegalStateException();
    }
    private GeneratedCert createCertificate(String cnName, String domain, GeneratedCert issuer, boolean isCA) throws Exception {
        // Generate the key-pair with the official Java API's
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        KeyPair certKeyPair = keyGen.generateKeyPair();
        X500Name name = new X500Name("CN=" + cnName);
        // If you issue more than just test certificates, you might want a decent serial number schema ^.^
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Instant validFrom = Instant.now();
        Instant validUntil = validFrom.plus(10 * 360, ChronoUnit.DAYS);

        // If there is no issuer, we self-sign our certificate.
        X500Name issuerName;
        PrivateKey issuerKey;
        if (issuer == null) {
            issuerName = name;
            issuerKey = certKeyPair.getPrivate();
        } else {
            issuerName = new X500Name(issuer.certificate.getSubjectDN().getName());
            issuerKey = issuer.privateKey;
        }

        // The cert builder to build up our certificate information
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerName,
                serialNumber,
                Date.from(validFrom), Date.from(validUntil),
                name, certKeyPair.getPublic());

        // Make the cert to a Cert Authority to sign more certs when needed
        if (isCA) {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCA));
        }
        // Modern browsers demand the DNS name entry
        if (domain != null) {
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, domain)));
        }

        // Finally, sign the certificate:
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(issuerKey);
        X509CertificateHolder certHolder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);

        return new GeneratedCert(certKeyPair.getPrivate(), cert);
    }
}
