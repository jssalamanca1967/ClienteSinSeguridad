/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package caso2infracomp;

import java.util.Date;
import javax.swing.JOptionPane;
import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

/**
 *
 * @author j.montes495
 */
public class Generator {

    private LoadGenerator generator;

    public Generator(int transacciones, int retardo) {
        
        int numberOfTasks = transacciones;
        int gapBetweenTasks = retardo;
        CVEscritor escritor = new CVEscritor("Cliente-Transacciones" + transacciones + "-Retrasos" + retardo + "-" + System.currentTimeMillis());

        Task work = createTask(escritor);

        generator = new LoadGenerator("Cliente - Servidor", numberOfTasks, work, gapBetweenTasks);
        generator.generate();

        escritor.cerrarArchivo();

    }

    private Task createTask(CVEscritor escritor) {
        return new ClientServerTask(escritor);
    }

    public static void main(String[] args) {

        String numThreadsParametro = JOptionPane.showInputDialog(null, "Retardos");
        int retardo = Integer.parseInt(numThreadsParametro);

        numThreadsParametro = JOptionPane.showInputDialog(null, "Número Transacciones");
        int transacciones = Integer.parseInt(numThreadsParametro);

        Generator generador = new Generator(transacciones, retardo);

    }

}
