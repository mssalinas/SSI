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
/*Incluimos todos aquellos paquetes de Java que nos harán falta para el desarrollo de la clase*/
import java.security.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

import java.io.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jcp.xml.dsig.internal.dom.Utils;

public class Empaquetar_exam {
    
     public static void mensajeAyuda() {
        System.out.println("Ejemplo cifrado DES");
        System.out.println("\tSintaxis:   java EjemploDES fichero");
        System.out.println();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException, FileNotFoundException, NoSuchProviderException, InvalidKeySpecException {

        if (args.length != 4) {
            mensajeAyuda();
            System.exit(1);
        }
        
        String pathExamen = args[0];
        String pathPaquete = args[1];
        String pathPublicaProfesor = args[2];
        String pathPrivadaAlumno = args[3];
        
        
        SecretKey claveSecreta = crearClaveSecreta();
        byte[] examen = Functions.leerFichero(pathExamen);
        byte[] examenCifrado = Functions.cifrarFichero(examen, claveSecreta);
        PublicKey publicaProfesor = Functions.leerPublica(pathPublicaProfesor);
        byte[] claveCifrada = cifrarClaveSecreta(claveSecreta, publicaProfesor);
        PrivateKey privadaAlumno = Functions.leerPrivada(pathPrivadaAlumno);
        byte[] firma = firmarDatos(examen, privadaAlumno);
        
        Bloque bloqueFichero = new Bloque("examen cifrado", examenCifrado);
        
        Bloque bloqueClaveCifrada = new Bloque("clave secreta cifrada", claveCifrada);
    
        Bloque bloqueFirma = new Bloque("firma", firma);
        
        Paquete p = new Paquete();
        
        p.anadirBloque("EXAMEN CIFRADO", bloqueFichero);
        p.anadirBloque("CLAVE CIFRADA", bloqueClaveCifrada);
        p.anadirBloque("FIRMA", bloqueFirma);
        
        PaqueteDAO.escribirPaquete(pathPaquete, p);
        
       
    }

private static SecretKey crearClaveSecreta() throws NoSuchAlgorithmException {
        KeyGenerator generadorDES = KeyGenerator.getInstance("DES"); // Obtenemos una instancia de KeyGenerator, en este caso usaremos el cifrado simétrico DES, este se obtiene mediante un patrón factoría.
        generadorDES.init(56); // Especificamos el tamaño de la clave DES
        SecretKey clave = generadorDES.generateKey(); //Generamos la clave de encriptación.
        return clave;
}

private static byte[] cifrarClaveSecreta (SecretKey claveSecreta, PublicKey publicaProfesor) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
    
      Cipher cifrador = Cipher.getInstance("RSA", "BC"); 
     // PASO 3a: Poner cifrador en modo CIFRADO 
      cifrador.init(Cipher.ENCRYPT_MODE, publicaProfesor);  // Cifra con la clave publica  
      return cifrador.doFinal(claveSecreta.getEncoded());
    
}
private static byte[] firmarDatos (byte[] examen, PrivateKey privadaAlumno) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
    
    MessageDigest messageDigest = MessageDigest.getInstance("MD5");
    
    byte[] resumen = messageDigest.digest(examen);
    
    System.out.println("RESUMEN:");
    mostrarBytes(resumen);
    System.out.println();
    
    Cipher cifrador = Cipher.getInstance("RSA", "BC");
    cifrador.init(1, privadaAlumno);
    byte[] resumenCifrado = cifrador.doFinal(resumen);
    
    return resumenCifrado;
}

public static void mostrarBytes(byte [] buffer) {
		System.out.write(buffer, 0, buffer.length);
	} 



}