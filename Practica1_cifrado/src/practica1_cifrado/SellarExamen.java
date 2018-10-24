/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package practica1_cifrado;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;
import java.util.Date;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


/**
 *
 * @author aero_
 */
public class SellarExamen {
    
        public static void mensajeAyuda() {
        System.out.println("Ejemplo cifrado DES");
        System.out.println("\tSintaxis:   java EjemploDES fichero");
        System.out.println();
    }
         
       public static void main(String[] args) throws NoSuchAlgorithmException, IOException, FileNotFoundException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
           
            if (args.length != 2) {
            mensajeAyuda();
            System.exit(1);
        }
           
           Signature firmaSellado = Signature.getInstance("MD5withRSA");
           
           Date fechaActual = Calendar.getInstance().getTime();
           byte[] bufferFechaActual = fechaActual.toString().getBytes();
           
           Paquete paquete = PaqueteDAO.leerPaquete(args[0]);
           
           Bloque bloqueFirma = paquete.getBloque("firma");
       
           
           PrivateKey clavePrivadaES= Functions.leerPrivada(args[1]);
           
           firmaSellado.initSign(clavePrivadaES);
           firmaSellado.update(bufferFechaActual);
           firmaSellado.update(bloqueFirma.getContenido());
           
           byte[] ficheroFirmado = firmaSellado.sign();
           
           byte[] ficheroCifrado = cifrarResumenClavePrivadaES(clavePrivadaES,ficheroFirmado);
           
           Bloque bloqueSellado = new Bloque ("BloqueSelloFirmado", ficheroCifrado);
           Bloque bloqueFecha = new Bloque ("Fecha",bufferFechaActual );
           
           paquete.anadirBloque(bloqueFecha);
           paquete.anadirBloque(bloqueSellado);
           
           PaqueteDAO.escribirPaquete(args[0], paquete);
           
       }
       
       private static byte[] cifrarResumenClavePrivadaES (PrivateKey clavePrivadaEntidadSellado, byte[] resumenSellado) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException{
           
         Cipher cifrador = Cipher.getInstance("RSA", "BC");
         
         cifrador.init(Cipher.ENCRYPT_MODE, clavePrivadaEntidadSellado); 
           
         byte[] resumenCifrado = cifrador.doFinal(resumenSellado);
        
         return resumenCifrado;
       }
     
}
