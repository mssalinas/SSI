/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package practica1_cifrado;

/**
 *
 * @author aero_
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class Functions {
    
    public Functions (){}
    
    public static byte[] leerFichero (String arg) throws FileNotFoundException, IOException {
        
                File examen = new File (arg);
                int tamañoExamen = (int) examen.length();
                byte[] buffer = new byte[tamañoExamen];

		FileInputStream in = new FileInputStream(examen);
		
		in.read(buffer, 0, tamañoExamen);

		in.close();
                
                return buffer;
       
        }
    
    public static byte[] cifrarFichero (byte [] fichero, SecretKey clave) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException{
        
        Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
        /* PASO 3b: Poner cifrador en modo DESCIFRADO */
	cifrador.init(Cipher.DECRYPT_MODE, clave);

        byte[] ficheroCifrado = cifrador.doFinal(fichero);
        return ficheroCifrado;   
    }
    
    public static PublicKey  leerPublica (String path) throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        
    File ficheroClavePublica = new File(path);
    int tamanoFicheroClavePublica = (int)ficheroClavePublica.length();
    byte[] bufferClavePublica = new byte[tamanoFicheroClavePublica];
    FileInputStream in = new FileInputStream(ficheroClavePublica);
    in.read(bufferClavePublica, 0, tamanoFicheroClavePublica);
    in.close();
    
    X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferClavePublica);
    
    KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
    
    return keyFactoryRSA.generatePublic(clavePublicaSpec);
        
    }
    
    public static PrivateKey leerPrivada (String path) throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        
    File ficheroClavePrivada = new File(path);
    int tamanoFicheroClavePrivada = (int)ficheroClavePrivada.length();
    byte[] bufferClavePrivada = new byte[tamanoFicheroClavePrivada];
    FileInputStream in = new FileInputStream(ficheroClavePrivada);
    in.read(bufferClavePrivada, 0, tamanoFicheroClavePrivada);
    in.close();
    
    X509EncodedKeySpec clavePrivadaSpec = new X509EncodedKeySpec(bufferClavePrivada);
    
    KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
    
    return keyFactoryRSA.generatePrivate(clavePrivadaSpec);
        
    }

     public static byte[] descifrarClavePublica(byte[] datos, PublicKey publicaSellado) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher descifrador = Cipher.getInstance("RSA","BC");
        descifrador.init(Cipher.DECRYPT_MODE,publicaSellado);
        return descifrador.doFinal(datos);
     }
    
}
