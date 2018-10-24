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
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import static practica1_cifrado.Empaquetar_exam.mensajeAyuda;

/**
 *
 * @author aero_
 */
public class DesempaquetarExamen {

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, FileNotFoundException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, IllegalBlockSizeException, IllegalBlockSizeException, IllegalBlockSizeException, IllegalBlockSizeException, BadPaddingException {
        if (args.length != 3) {
            mensajeAyuda();
            System.exit(1);
        }
        
        String pathPaquete = args[0];
        String pathClaves = args[1];
        String rutaGuardado = args[2];
        boolean iguales = true;

        MessageDigest messageDigest = MessageDigest.getInstance("MD5"); // Instanciamos MessageDigest con MD5
        PublicKey publicaSellado = Functions.leerPublica(pathClaves);

        Paquete paqueteExamen = PaqueteDAO.leerPaquete("pathPaquete"); // Leemos el Paquete
        
        Bloque bloqueFirma = paqueteExamen.getBloque("FIRMA");
        Bloque bloqueFecha = paqueteExamen.getBloque("FECHA");
        Bloque bloqueSello = paqueteExamen.getBloque("SELLO");
        
        // Obtenemos el contenido de los tres bloques que vamos a necesitar para saber si el fichero fué modificado
        byte[] contentBloqueFirma = bloqueFirma.getContenido();
        byte[] contentBloqueFecha = bloqueFirma.getContenido();
        byte[] contentBloqueSello = bloqueFirma.getContenido();
        
        // Añadimos a messageDigest el contenido de los bloques Fecha y Firma
        messageDigest.update(contentBloqueFecha);
        messageDigest.update(contentBloqueFirma);
        
        // Obtenemos los dos resumenes que vamos a necesitar comprobar
        byte[] resumenRecibidoFinal = messageDigest.digest(); // El resumen que acabamos de crear con la Firma y la Fecha
        byte[] resumenEnviadoFinal = Functions.descifrarClavePublica(contentBloqueSello, publicaSellado); // Simplemente lo obtenemos ya del paquete sellado(SELLO FIRMADO)
        
        //Comprobación
        equals(resumenRecibidoFinal,resumenEnviadoFinal);
                

}
    
// Función para comprobar que dos ficheros son iguales
  public static void equals(byte[] a, byte[] b){
   boolean iguales=true;
        if (a.length!= b.length) {
            System.out.println("Ficheros distintos. Tamaño diferente");
        } else {
           for (int i = 0; i < a.length; i++) {
                if (a[i] != b[i]) {
                    iguales = false;
                }
            }
        }
        if (iguales == false) {
            System.out.println("Los ficheros fueron modificados");
        } else {
            System.out.println("Ficheros iguales. OK");
        }
}
}