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
public class Bloque {
    private String nombre;
    private byte[] contenido;

    public Bloque() {
    }

    
    public Bloque(String nombre, byte[] contenido) {
        this.nombre = nombre;
        this.contenido = contenido;
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    
    
    public byte[] getContenido() {
        return contenido;
    }

    public void setContenido(byte[] contenido) {
        this.contenido = contenido;
    }

    public String toString() {
	if (contenido != null) {
        	return this.nombre+": ["+contenido.length+" posiciones]";
	}
	else {
        	return this.nombre+": [vacio]";
	}
    }
        
}