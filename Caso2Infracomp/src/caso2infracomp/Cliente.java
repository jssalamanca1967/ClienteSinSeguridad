package caso2infracomp;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;

import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.X509Extensions;

import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import sun.security.x509.X509CertImpl;
import static utils.Seguridad.generateRSAKeyPair;

public class Cliente extends Thread {

    public final static int PUERTO = 443;

    public final static String HOST = "127.0.0.1";

    //-------------------------
    // Cadenas de control
    //-------------------------
    public final static String INFORMAR = "INFORMAR";
    public final static String EMPEZAR = "EMPEZAR";
    public final static String ALGORITMOS = "ALGORITMOS";
    public final static String RTA = "RTA";
    public final static String OK = "OK";
    public final static String ERROR = "ERROR";
    public final static String CERTPA = "CERTPA";
    public final static String CERTSRV = "CERTSRV";
    public final static String ORDENES = "ORDENES";

    //------------------------
    // Algoritmos
    //-----------------------
    public final static String RSA = "RSA";
    public final static String HMACMD5 = "HMACMD5";
    public final static String HMACSHA1 = "HMACSHA1";
    public final static String HMACSHA256 = "HMACSHA256";

    /*
     Hay muchos. Se escogió uno al azar
    
     Algorithm name: GOST3411WITHGOST3410
     Algorithm name: SHA384WITHRSA
     Algorithm name: RIPEMD160WITHRSAENCRYPTION
     Algorithm name: SHA512WITHRSAENCRYPTION
     Algorithm name: MD2WITHRSA
     Algorithm name: SHA384WITHRSAENCRYPTION
     Algorithm name: SHA1WITHRSAANDMGF1
     Algorithm name: SHA384WITHRSAANDMGF1
     Algorithm name: MD2WITHRSAENCRYPTION
     Algorithm name: SHA256WITHECDSA
     Algorithm name: RIPEMD128WITHRSAENCRYPTION
     Algorithm name: DSAWITHSHA1
     Algorithm name: GOST3411WITHGOST3410-94
     Algorithm name: SHA512WITHECDSA
     Algorithm name: MD5WITHRSA
     Algorithm name: SHA224WITHRSA
     Algorithm name: SHA1WITHRSAENCRYPTION
     Algorithm name: SHA512WITHRSA
     Algorithm name: SHA256WITHDSA
     Algorithm name: RIPEMD128WITHRSA
     Algorithm name: SHA256WITHRSAENCRYPTION
     Algorithm name: RIPEMD160WITHRSA
     Algorithm name: SHA1WITHDSA
     Algorithm name: SHA224WITHECDSA
     Algorithm name: MD5WITHRSAENCRYPTION
     Algorithm name: SHA1WITHECDSA
     Algorithm name: GOST3411WITHGOST3410-2001
     Algorithm name: SHA224WITHRSAANDMGF1
     Algorithm name: SHA384WITHECDSA
     Algorithm name: RIPEMD256WITHRSA
     Algorithm name: ECDSAWITHSHA1
     Algorithm name: SHA256WITHRSA
     Algorithm name: SHA256WITHRSAANDMGF1
     Algorithm name: GOST3411WITHECGOST3410-2001

     */
    public final static String ALGORITMO_CERTIFICADO = "MD2WITHRSA";

    //-----------------------
    // Atributos
    //-----------------------
    /**
     * ALG-A
     */
    public String algoritmoA;

    /**
     * ALG-HMAC
     */
    public String algoritmoHMAC;

    public X509Certificate certificadoPA;
    public X509Certificate certificadoServidor;

    private Socket socket;
    private PrintWriter escritor;
    private BufferedReader lector;
    private String numeroPA;
    private String numeroServidor;
    private PrivateKey caKey;

    private KeyPair parLlaves;

    private PublicKey llavePublicaServidor;

    private SecretKey llaveSimetrica;

    private Cipher cifrador;

    private String aEnviar;
    private String recibido;
    private String[] rta1;
    private CVEscritor generadorArchivo;

    private Long tiempoAunt1;

    private Long tiempoAunt2;

    public Cliente(CVEscritor escritorP) {

        try {
            generadorArchivo = escritorP;
            cifrador = Cipher.getInstance(RSA);
        } catch (Exception ex) {

            ex.printStackTrace();
            escribirEnArchivo("Fallo", ex.getMessage());
//            generadorArchivo.escribirLinea("Fallo", ex.getMessage());

        }

    }

    public void imprimirConsola(String asdf) {
        System.out.println(asdf);
    }

    public void enviarMensaje(String mensaje) {

        escritor.append(mensaje + "\n");
        escritor.flush();

        imprimirConsola("C: " + mensaje);

    }

    private void generarParDeLlaves() throws NoSuchAlgorithmException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        parLlaves = keyGen.generateKeyPair();

    }

    public void iniciarConexion() {

        try {

            socket = null;
            escritor = null;
            lector = null;

            System.out.println("Inicializando");
            try {

                socket = new Socket(HOST, PUERTO);
                escritor = new PrintWriter(socket.getOutputStream(), true);
                lector = new BufferedReader(new InputStreamReader(
                        socket.getInputStream()));

                imprimirConsola("Se inicializó el socket");

            } catch (Exception ex) {

                ex.printStackTrace();
                escribirEnArchivo("Fallo", ex.getMessage());
//                generadorArchivo.escribirLinea("Fallo", ex.getMessage());

            }

        } catch (Exception ex) {

            ex.printStackTrace();
            escribirEnArchivo("Fallo", ex.getMessage());
//            generadorArchivo.escribirLinea("Fallo", ex.getMessage());

        }

    }

    public void cerrarConexion() {
        try {
            escritor.close();
            lector.close();
            socket.close();

        } catch (Exception ex) {

            ex.printStackTrace();
            escribirEnArchivo("Fallo", ex.getMessage());
//            generadorArchivo.escribirLinea("Fallo", ex.getMessage());

        }

    }
    
    public synchronized void escribirEnArchivo(String linea, String dato){
        
        generadorArchivo.escribirLinea(linea, dato);
        
    }

    private void crearYEnviarCertificado() {

        try {

            Date fechaInicio = new Date();
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(fechaInicio);
            calendar.add(Calendar.DATE, 5);

            Date expiracion = calendar.getTime();              // time after which certificate is not valid
            BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());       // serial number for certificate
            PrivateKey caKey = parLlaves.getPrivate();              // private key of the certifying authority (ca) certificate
            X509Certificate caCert = certificadoServidor;        // public key certificate of the certifying authority
            KeyPair keyPair = parLlaves;               // public/private key pair that we are creating certificate for

            X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
            X500Principal subjectName = new X500Principal("CN=Test V3 Certificate");
            X500Principal issuer = new X500Principal("CN=InfraCompOP");

            generator.setSerialNumber(serialNumber);
            //generator.setIssuerDN(caCert.getSubjectX500Principal());
            generator.setIssuerDN(issuer);
            generator.setNotBefore(fechaInicio);
            generator.setNotAfter(expiracion);
            generator.setSubjectDN(subjectName);
            generator.setPublicKey(keyPair.getPublic());
            generator.setSignatureAlgorithm(ALGORITMO_CERTIFICADO);

            certificadoPA = generator.generate(parLlaves.getPrivate());  // note: private key of CA
            System.out.println(certificadoPA.getIssuerDN().toString());

            byte[] data = certificadoPA.getEncoded();

            socket.getOutputStream().write(data);
            socket.getOutputStream().flush();

            imprimirConsola("C: Enviando certificado");

//            return cert;
//            imprimirConsola("holiz" + cert);// note: private key of CA
        } catch (Exception ex) {

            ex.printStackTrace();
            generadorArchivo.escribirLinea("Fallo", ex.getMessage());

        }

    }

    public void etapa1() throws Exception {
        //-----------------------------------
        // Creando conexión
        aEnviar = INFORMAR;

        enviarMensaje(aEnviar);

        recibido = lector.readLine();

        imprimirConsola("S: " + recibido);

        if (recibido != null && !recibido.isEmpty()) {
            if (!recibido.equals(EMPEZAR)) {
                System.err.println("Exception: El servidor no respondio como se esperaba."
                        + "\nRespuesta: " + recibido);
                escribirEnArchivo("Fallo", "El servidor no respondio como se esperaba");
//                generadorArchivo.escribirLinea("Fallo", "El servidor no respondio como se esperaba");
            }

        }

        //--------------------------------------------------
        // Negociando algoritmos
        // HMAC5D escogido arbitrariamente
        algoritmoA = RSA;
        algoritmoHMAC = HMACMD5;

        aEnviar = ALGORITMOS + ":" + algoritmoA + ":" + algoritmoHMAC;

        enviarMensaje(aEnviar);

        recibido = lector.readLine();

        imprimirConsola("S: " + recibido);

        String[] rta1 = recibido.split(":");

        if (recibido != null && !recibido.isEmpty()) {
            if (rta1.length != 2) {
                System.err.println("Exception: El servidor no respondio como se esperaba."
                        + "\nRespuesta: " + recibido);
                escribirEnArchivo("Fallo", "El servidor no respondio como se esperaba");
//                generadorArchivo.escribirLinea("Fallo", "El servidor no respondio como se esperaba");
            }
        }

        if (!rta1[0].equals(RTA) && !rta1[1].equals(OK)) {
            if (rta1[1].equals(ERROR)) {
                System.err.println("Exception: El servidor no respondio como se esperaba."
                        + "\nRespuesta: " + recibido);

            } else {
                System.err.println("Exception: El servidor no respondio como se esperaba."
                        + "\nRespuesta: " + recibido);
                escribirEnArchivo("Fallo", "El servidor no respondio como se esperaba");
//                generadorArchivo.escribirLinea("Fallo", "El servidor no respondio como se esperaba");
            }
        }

    }

    public void etapa2() throws Exception {

        //-------------------------------------------------------------------
        // Envio del certificado
        numeroPA = "" + ((int) (Math.random() * 100));

        aEnviar = "" + numeroPA + ":" + CERTPA;

        enviarMensaje(aEnviar);

        generarParDeLlaves();

        crearYEnviarCertificado();

        recibido = lector.readLine();

        imprimirConsola("S: " + recibido);

        rta1 = recibido.split(":");

        if (recibido != null && !recibido.isEmpty()) {
            if (rta1.length != 2) {
                System.err.println("Exception: El servidor no respondio como se esperaba."
                        + "\nRespuesta: " + recibido);
                escribirEnArchivo("Fallo", "El servidor no respondio como se esperaba");
//                generadorArchivo.escribirLinea("Fallo", "El servidor no respondio como se esperaba");
            }
        }

        if (!rta1[0].equals(RTA) && !rta1[1].equals(OK)) {
            if (rta1[1].equals(ERROR)) {
                System.err.println("Exception: El servidor no respondio como se esperaba."
                        + "\nRespuesta: " + recibido);

            } else {
                System.err.println("Exception: El servidor no respondio como se esperaba."
                        + "\nRespuesta: " + recibido);
                escribirEnArchivo("Fallo", "El servidor no respondio como se esperaba");
//                generadorArchivo.escribirLinea("Fallo", "El servidor no respondio como se esperaba");
            }
        }

        //-------------------------------------------------------------------
        // Recepción del certificado
        recibido = lector.readLine();

        imprimirConsola("S: " + recibido);

        rta1 = recibido.split(":");

        if (recibido != null && !recibido.isEmpty()) {
            if (rta1.length != 2) {
                System.err.println("Exception: El servidor no respondio como se esperaba."
                        + "\nRespuesta: " + recibido);
                escribirEnArchivo("Fallo", "El servidor no respondio como se esperaba");
//                generadorArchivo.escribirLinea("Fallo", "El servidor no respondio como se esperaba");
            }
        }

        imprimirConsola(rta1[1]);

        if (!rta1[1].equals(CERTSRV)) {

            System.err.println("Exception: El servidor no respondio como se esperaba."
                    + "\nRespuesta: " + recibido);
            escribirEnArchivo("Fallo", "El servidor no respondio como se esperaba");
//            generadorArchivo.escribirLinea("Fallo", "El servidor no respondio como se esperaba");

        }

        try {

            numeroServidor = rta1[0];
        } catch (NumberFormatException e) {

            System.err.println("Exception: El servidor no respondio como se esperaba."
                    + "\nRespuesta: " + recibido);
            escribirEnArchivo("Fallo", "El servidor no respondio como se esperaba");
//            generadorArchivo.escribirLinea("Fallo", "El servidor no respondio como se esperaba");
        }

        try {

            certificadoServidor = obtenerCertificadoServidor();
        } catch (Exception e) {

            e.printStackTrace();
            escribirEnArchivo("Fallo", e.getMessage());
//            generadorArchivo.escribirLinea("Fallo", e.getMessage());
        }
        tiempoAunt2 = System.currentTimeMillis();

        if (tiempoAunt2 == null || tiempoAunt1 == null) {
            escribirEnArchivo("Fallo", "El servidor no respondio como se esperaba");
//            generadorArchivo.escribirLinea("Fallo", "El servidor no respondio como se esperaba");
        } else {
            escribirEnArchivo("TiempoAuntenticacion", "" + (tiempoAunt2 - tiempoAunt1));
//            generadorArchivo.escribirLinea("TiempoAuntenticacion", (tiempoAunt2 - tiempoAunt1) + "");
        }
    }

    public void etapa3() throws Exception {

        //-------------------------------------------------------------------
        // Respondiendo y recibiendo número cifrado
        aEnviar = RTA + ":" + OK;

        enviarMensaje(aEnviar);

        recibido = lector.readLine();

        imprimirConsola("S: " + recibido);

        int asdf = recibido.compareTo(numeroPA);

        imprimirConsola(asdf + " - " + recibido + " - " + numeroPA);

        if (!recibido.equals(numeroPA)) {
            System.err.println("Exception: El servidor envio un numero inválido"
                    + "\nRespuesta: " + recibido);
            escribirEnArchivo("Fallo", "El servidor no respondio como se esperaba");

//            generadorArchivo.escribirLinea("Fallo", "El servidor envio un numero invalido");
            
        }

        imprimirConsola(recibido + " - " + numeroPA);

        aEnviar = RTA + ":" + OK;

        enviarMensaje(aEnviar);

        aEnviar = numeroServidor;

        enviarMensaje(aEnviar);

        recibido = lector.readLine();

        imprimirConsola("S: " + recibido);

        rta1 = recibido.split(":");

        if (recibido != null && !recibido.isEmpty()) {
            if (rta1.length != 2) {
                System.err.println("Exception: El servidor no respondio como se esperaba."
                        + "\nRespuesta: " + recibido);
                escribirEnArchivo("Fallo", "El servidor no respondio como se esperaba");
//                generadorArchivo.escribirLinea("Fallo", "El servidor no respondio como se esperaba");
            }
        }

        if (!rta1[0].equals(RTA) && !rta1[1].equals(OK)) {
            if (rta1[1].equals(ERROR)) {
                System.err.println("Exception: El servidor no respondio como se esperaba."
                        + "\nRespuesta: " + recibido);

            } else {
                System.err.println("Exception: El servidor no respondio como se esperaba."
                        + "\nRespuesta: " + recibido);
                escribirEnArchivo("Fallo", "El servidor no respondio como se esperaba");
//                generadorArchivo.escribirLinea("Fallo", "El servidor no respondio como se esperaba");
            }
        }

    }

    public void etapa4() throws Exception {

//        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
//
//        llaveSimetrica = keyGen.generateKey();
//        Mac macAlgo = Mac.getInstance(algoritmoHMAC);
//
//        macAlgo.init(llaveSimetrica);
//
//        // Se cifra con la llave publica del servidor
//        Cipher cifradorPublico = Cipher.getInstance(RSA);
//        cifradorPublico.init(Cipher.ENCRYPT_MODE, llavePublicaServidor);
//
//        byte[] data = macAlgo.doFinal(llaveSimetrica.getEncoded());
//
//        byte[] primerCifrado = cifradorPublico.doFinal(data);
//
//        Cipher cifradoPrivado = Cipher.getInstance(RSA);
//        cifradoPrivado.init(Cipher.ENCRYPT_MODE, parLlaves.getPrivate());
//
//        // Cifrado por bloques
//        aEnviar = "";
//
//        int numero = primerCifrado.length / 117;
//
//        for (int i = 0; i < numero; i++) {
//            byte[] nuevoCifrado = new byte[117];
//            for (int j = i * 117; j < 117 + i * (primerCifrado.length - 117); j++) {
//
//                int m = 0;
//                nuevoCifrado[m] = primerCifrado[j];
//
//                m++;
//
//            }
//
//            byte[] segundoCifrado = cifradoPrivado.doFinal(nuevoCifrado);
//
//            aEnviar += Transformacion.transformar(segundoCifrado);
//
//        }

        enviarMensaje("INIT");
    }

    public void run() {

        try {
            tiempoAunt1 = System.currentTimeMillis();
            iniciarConexion();

            etapa1();
            etapa2();
            etapa3();
            etapa4();

            cerrarConexion();
        } catch (Exception e) {

            imprimirConsola("---> Se lanzó este error");

            e.printStackTrace();
            generadorArchivo.escribirLinea("Fallo", e.getMessage());

        }

    }

    private X509Certificate obtenerCertificadoServidor() throws Exception {

        X509Certificate cert = null;

        InputStream llegada = socket.getInputStream();

        byte[] arr = new byte[520];

        System.out.println(llegada.read(arr));

        InputStream insa = new ByteArrayInputStream(arr);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) certFactory.generateCertificate(insa);

        System.out.println("Servidor: " + cert);
        llavePublicaServidor = cert.getPublicKey();

        return cert;

    }

    private String descifrarAsimetrico(String input) throws Exception {

        String rta = "";

        byte[] datos = Transformacion.destransformar(input);
        cifrador.init(Cipher.DECRYPT_MODE, llavePublicaServidor);

        byte[] clearText = new byte[1024];

        clearText = cifrador.doFinal(datos);
        //s3 = new String(clearText); 
        System.out.println("clave original: " + clearText);

        rta = new String(clearText);

        imprimirConsola(rta + " - " + numeroPA);

        return rta;

    }

    private String encriptarAsimetrico(String texto) throws Exception {

        String rta = "";

        imprimirConsola(texto);

        byte[] datos = texto.getBytes();

        cifrador.init(Cipher.ENCRYPT_MODE, parLlaves.getPrivate());

        byte[] clearText = cifrador.doFinal(datos);

        rta = Transformacion.transformar(clearText);

        return rta;

    }

}
