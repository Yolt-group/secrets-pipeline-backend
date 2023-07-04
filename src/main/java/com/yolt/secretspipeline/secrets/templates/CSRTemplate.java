package com.yolt.secretspipeline.secrets.templates;


import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import org.springframework.lang.Nullable;

import java.util.List;
import java.util.Set;

@Builder(toBuilder = true)
@EqualsAndHashCode
@ToString
@RequiredArgsConstructor
public class CSRTemplate {

    /**
     * Subject represented by distinguished names such as "CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US".
     */
    @NonNull
    public final String subject;

    /**
     * Strength of RSA key, can be 2048 or 4096
     */
    @NonNull
    public final Integer strength;

    /**
     * SignatureAlgorithm, can be SHA256withRSA, SHA384withRSA, SHA512withRSA
     */
    @NonNull
    public final String signatureAlgorithm;

    /**
     * KeyUsage
     * <ul><li>digitalSignature</li>
     * <li>nonRepudiation</li>
     * <li>keyEncipherment</li>
     * <li>dataEncipherment</li>
     * <li>keyAgreement</li>
     * <li>keyCertSign</li>
     * <li>cRLSign</li>
     * <li>encipherOnly</li>
     * <li>decipherOnly</li></ul>
     */
    @Nullable
    public final Set<String> keyUsage;

    /**
     * ExtendedKeyUsage
     * <ul><li>serverAuth</li>
     * <li>clientAuth</li>
     * <li>codeSigning</li>
     * <li>emailProtection</li>
     * <li>ipsecEndSystem</li>
     * <li>ipsecTunnel</li>
     * <li>ipsecUser</li>
     * <li>timeStamping</li>
     * <li>OCSPSigning</li>
     * <li>dvcs</li>
     * <li>sbgpCertAAServerAuth</li>
     * <li>scvp_responder</li>
     * <li>eapOverPPP</li>
     * <li>eapOverLAN</li>
     * <li>scvpServer</li>
     * <li>scvpClient</li>
     * <li>ipsecIKE</li>
     * <li>capwapAC</li>
     * <li>capwapWTP</li>
     * <li>smartcardlogon</li>
     * <li>macAddress</li>
     * <li>msSGC</li>
     * <li>nsSGC</li></ul>
     */
    @Nullable
    public final Set<String> extendedKeyUsage;

    /**
     * subjectAlternativeNames, can only be DNSNames
     */
    @Nullable
    public final List<String> subjectAlternativeNames;

}

