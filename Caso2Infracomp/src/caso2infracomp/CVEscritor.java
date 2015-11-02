package caso2infracomp;

import java.io.*;
import java.io.IOException;
import java.util.ArrayList;

public class CVEscritor {

//    private FileWriter writer;
    
    private String sFileName;
    
    private int contador;
    
    private ArrayList<String> escritos;

    public CVEscritor(String nombreArchivo) {
        
        escritos = new ArrayList<String>();
        
        contador = 0;
        
        sFileName = "./data/" + nombreArchivo + ".csv";
        
        try {
            File archivo = new File(sFileName);
            if (!archivo.exists()) {
                archivo.createNewFile();
            }
//            writer = new FileWriter(nombreArchivo);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void escribirLinea(String linea, String dato) {
        try {
            contador++;
            
            String aEscribir = contador + "," + linea + "," + dato + "\n";
            
            escritos.add(aEscribir);
            
            FileWriter writer = new FileWriter(sFileName);
                        
            for(int i = 0; i < escritos.size(); i++){
                writer.append(escritos.get(i));
            }
            
//            writer.append("" + contador);
//            writer.append(',');
//            writer.append(linea);
//            writer.append(',');
//            writer.append(dato);
//            writer.append('\n');
            writer.flush();
            writer.close();

        } catch (Exception e) {
            e.printStackTrace();
            cerrarArchivo();
        }

    }

    public void cerrarArchivo() {
        // generate whatever data you want

        try {
//            writer.flush();
//            writer.close();
        } catch (Exception e) {

        }
    }
}
